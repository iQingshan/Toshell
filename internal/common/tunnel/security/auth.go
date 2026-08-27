package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TLSConfig struct {
	CertFile    string
	KeyFile     string
	CAFile      string
	ServerName  string
	MinVersion  uint16
	Insecure    bool
}

func NewServerTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil || cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("cert file and key file are required")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("load ca: %w", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	if cfg.MinVersion != 0 {
		tlsConfig.MinVersion = cfg.MinVersion
	}

	return tlsConfig, nil
}

func NewClientTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg != nil {
		if cfg.ServerName != "" {
			tlsConfig.ServerName = cfg.ServerName
		}

		if cfg.Insecure {
			tlsConfig.InsecureSkipVerify = true
		}

		if cfg.MinVersion != 0 {
			tlsConfig.MinVersion = cfg.MinVersion
		}

		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		if cfg.CAFile != "" {
			caCert, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("load ca: %w", err)
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			tlsConfig.RootCAs = caCertPool
		}
	}

	return tlsConfig, nil
}

type TokenAuth struct {
	secretKey   []byte
	tokenExpiry time.Duration
	issuer      string
}

type TokenClaims struct {
	SessionID string `json:"session_id"`
	Role      string `json:"role"`
	jwt.RegisteredClaims
}

type TokenAuthOption func(*TokenAuth)

func WithTokenExpiry(d time.Duration) TokenAuthOption {
	return func(ta *TokenAuth) {
		ta.tokenExpiry = d
	}
}

func WithIssuer(issuer string) TokenAuthOption {
	return func(ta *TokenAuth) {
		ta.issuer = issuer
	}
}

func NewTokenAuth(secretKey string, opts ...TokenAuthOption) *TokenAuth {
	ta := &TokenAuth{
		secretKey:   []byte(secretKey),
		tokenExpiry: 24 * time.Hour,
		issuer:      "toshell",
	}

	for _, opt := range opts {
		opt(ta)
	}

	return ta
}

func (ta *TokenAuth) GenerateToken(sessionID, role string) (string, error) {
	claims := TokenClaims{
		SessionID: sessionID,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ta.tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    ta.issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(ta.secretKey)
}

func (ta *TokenAuth) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ta.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (ta *TokenAuth) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			claims, err := ta.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "session_id", claims.SessionID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetSessionID(ctx context.Context) string {
	if v := ctx.Value("session_id"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func GetRole(ctx context.Context) string {
	if v := ctx.Value("role"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

type AuthConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

type Auth struct {
	config *AuthConfig
}

func NewAuth(cfg *AuthConfig) *Auth {
	return &Auth{config: cfg}
}

func (a *Auth) ValidateCredentials(username, password string) bool {
	if a.config == nil || !a.config.Enabled {
		return true
	}
	return a.config.Username == username && a.config.Password == password
}

func (a *Auth) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.config == nil || !a.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "authenticated", true)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
