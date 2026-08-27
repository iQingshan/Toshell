package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"toshell/internal/server/config"
)

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type Auth struct {
	Config *config.AuthConfig
}

func New(cfg *config.AuthConfig) *Auth {
	return &Auth{Config: cfg}
}

// Update 运行时替换认证配置（设置 API 保存后调用，实现热生效）。
func (a *Auth) Update(cfg *config.AuthConfig) {
	if a != nil && cfg != nil {
		a.Config = cfg
	}
}

func (a *Auth) GenerateToken(username, role string) (string, error) {
	if !a.Config.JWTEnabled {
		return "", errors.New("JWT is not enabled")
	}

	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(a.Config.JWTExpire))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "toshell",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(a.Config.JWTKey))
}

func (a *Auth) ValidateToken(tokenString string) (*Claims, error) {
	if !a.Config.JWTEnabled {
		return nil, errors.New("JWT is not enabled")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.Config.JWTKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// CheckPassword compares a bcrypt hashed password against a plaintext password.
func (a *Auth) CheckPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// ValidateCredentials validates username and password.
// Supports bcrypt hashed passwords ($2a$ prefix) with plaintext fallback for backward compatibility.
func (a *Auth) ValidateCredentials(username, password string) bool {
	if !a.Config.Enabled {
		return true
	}

	if subtle.ConstantTimeCompare([]byte(username), []byte(a.Config.AdminUsername)) != 1 {
		return false
	}

	// If the stored password is a bcrypt hash (starts with "$2a$"), use bcrypt comparison
	if strings.HasPrefix(a.Config.AdminPassword, "$2a$") {
		return a.CheckPassword(a.Config.AdminPassword, password)
	}

	// Fallback to constant-time comparison for plaintext passwords
	return subtle.ConstantTimeCompare([]byte(password), []byte(a.Config.AdminPassword)) == 1
}

// HashPassword generates a bcrypt hash from a plaintext password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// GenerateRandomKey generates a cryptographically random key as a base64-encoded string.
// 'length' is the number of random bytes to generate.
func GenerateRandomKey(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (a *Auth) ValidateAPIKey(apiKey string) bool {
	if !a.Config.APIKeyEnabled {
		return true
	}

	for _, key := range a.Config.APIKeys {
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(key)) == 1 {
			return true
		}
	}

	return false
}

func (a *Auth) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.Config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			apiKey := r.Header.Get("X-API-Key")
			if apiKey != "" && a.Config.APIKeyEnabled {
				if a.ValidateAPIKey(apiKey) {
					next.ServeHTTP(w, r)
					return
				}
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && a.Config.JWTEnabled {
				parts := strings.Split(authHeader, " ")
				if len(parts) == 2 && parts[0] == "Bearer" {
					claims, err := a.ValidateToken(parts[1])
					if err == nil && claims != nil {
						r.Header.Set("X-Username", claims.Username)
						r.Header.Set("X-Role", claims.Role)
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			token := r.URL.Query().Get("token")
			if token != "" && a.Config.JWTEnabled {
				claims, err := a.ValidateToken(token)
				if err == nil && claims != nil {
					r.Header.Set("X-Username", claims.Username)
					r.Header.Set("X-Role", claims.Role)
					next.ServeHTTP(w, r)
					return
				}
			}

			if r.URL.Path == "/api/v1/login" || r.URL.Path == "/api/v1/health" {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if !a.Config.Enabled {
		token, _ := a.GenerateToken(username, "admin")
		w.Write([]byte(`{"token":"` + token + `"}`))
		return
	}

	if a.ValidateCredentials(username, password) {
		token, err := a.GenerateToken(username, "admin")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"token":"` + token + `"}`))
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}
