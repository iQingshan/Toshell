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

// tokenQueryAllowed 判断该请求路径是否允许用 `?token=<JWT>` 认证。
//
// 只对浏览器发起的 WebSocket 放行，因为浏览器的 WebSocket API **无法自定义请求头**
// （不能带 Authorization / X-API-Key），`?token=` 是前端唯一可用的传参方式；
// 事件流（含实时屏幕帧）统一走 /api/v1/ws/events，交互式 shell 走
// /api/v1/sessions/{id}/shell。除此之外的管理 API 一律必须走 Authorization: Bearer，
// 避免 JWT 落进 Nginx/代理访问日志、浏览器历史与 Referer（审计 M6）。
//
// 注意：这里做的是**纯函数**，不读配置、不发请求，便于单测覆盖（回归测试见 auth_test.go）。
func tokenQueryAllowed(path string) bool {
	if path == "/api/v1/ws/events" {
		return true
	}
	// /api/v1/sessions/{id}/shell 及其子路径（如将来新增 /shell/xxx），id 不能为空。
	const prefix = "/api/v1/sessions/"
	if strings.HasPrefix(path, prefix) {
		rest := strings.TrimPrefix(path, prefix)
		if i := strings.IndexByte(rest, '/'); i > 0 {
			tail := rest[i:]
			return tail == "/shell" || strings.HasPrefix(tail, "/shell/")
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

			// `?token=` 仅对 WebSocket 路径放行（浏览器 WS API 不能自定义请求头）。
			// 其它路径一律忽略查询串里的 token —— 即使 JWT 本身有效也按未认证处理，
			// 并在响应里给出可辨识原因，避免「以为是 token 过期」这类误判。
			token := r.URL.Query().Get("token")
			queryTokenAllowed := tokenQueryAllowed(r.URL.Path)
			if token != "" && a.Config.JWTEnabled && queryTokenAllowed {
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

			if token != "" && a.Config.JWTEnabled && !queryTokenAllowed {
				// 401 而不是 403：语义上仍是「未认证」；文本里点名正确用法，便于排障。
				http.Error(w, "Unauthorized: token must be sent via Authorization header (query token is only accepted for WebSocket endpoints)", http.StatusUnauthorized)
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
