package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	authCookieName      = "auth_token"
	authCookieMaxAgeSec = 72 * 3600
)

func (s *APIServer) setAuthCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   authCookieMaxAgeSec,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cfg.AuthCookieSecure,
	})
}

func (s *APIServer) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cfg.AuthCookieSecure,
	})
}

func bearerOrCookieJWT(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	c, err := r.Cookie(authCookieName)
	if err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// accountBannedForHTTP 与代理签名校验中的封禁逻辑一致：封禁期内或永久封禁则禁止 Web 会话访问。
func accountBannedForHTTP(u User) bool {
	if u.Status != "banned" {
		return false
	}
	if !u.BanUntil.Valid {
		return true
	}
	t, err := time.Parse(time.RFC3339, u.BanUntil.String)
	if err != nil {
		return true
	}
	return t.After(time.Now())
}

func (s *APIServer) findUserByAppID(appID string) (User, error) {
	var u User
	var secretShown int
	err := s.db.QueryRow(`SELECT id,email,password_hash,app_id,app_secret,secret_shown,role,status,ban_reason,ban_until,created_at
		FROM users WHERE app_id=?`, appID).
		Scan(&u.ID, &u.Email, &u.Password, &u.AppID, &u.AppSecret, &secretShown, &u.Role, &u.Status, &u.BanReason, &u.BanUntil, &u.CreatedAt)
	if err != nil {
		return u, err
	}
	u.SecretSeen = secretShown == 1
	u.AppSecret, err = unsealAppSecret(u.AppSecret, s.cfg.SecretWrapKey)
	return u, err
}

func (s *APIServer) makeJWT(u User) (string, error) {
	claims := authClaims{
		UserID: u.ID,
		Role:   u.Role,
		Email:  u.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "anilink-proxy",
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(s.cfg.JWTSecret))
}

func (s *APIServer) parseJWT(tokenStr string) (User, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &authClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return User{}, errors.New("invalid token")
	}
	claims, ok := token.Claims.(*authClaims)
	if !ok {
		return User{}, errors.New("invalid token claims")
	}
	var u User
	var secretShown int
	err = s.db.QueryRow(`SELECT id,email,password_hash,app_id,app_secret,secret_shown,role,status,ban_reason,ban_until,created_at
		FROM users WHERE id=?`, claims.UserID).
		Scan(&u.ID, &u.Email, &u.Password, &u.AppID, &u.AppSecret, &secretShown, &u.Role, &u.Status, &u.BanReason, &u.BanUntil, &u.CreatedAt)
	if err != nil {
		return u, err
	}
	u.SecretSeen = secretShown == 1
	u.AppSecret, err = unsealAppSecret(u.AppSecret, s.cfg.SecretWrapKey)
	return u, err
}

type ctxKey string

const userCtxKey ctxKey = "user"

func (s *APIServer) authUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerOrCookieJWT(r)
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing credentials", nil)
			return
		}
		u, err := s.parseJWT(tok)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token", nil)
			return
		}
		if accountBannedForHTTP(u) {
			writeJSON(w, http.StatusForbidden, "BANNED", "account banned", nil)
			return
		}
		// 将鉴权后的用户信息注入上下文，后续 handler 统一从 ctx 读取。
		ctx := context.WithValue(r.Context(), userCtxKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *APIServer) authAdminMiddleware(next http.Handler) http.Handler {
	return s.authUserMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := userFromCtx(r.Context())
		if u.Role != roleAdmin {
			writeJSON(w, http.StatusForbidden, "FORBIDDEN", "admin only", nil)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func userFromCtx(ctx context.Context) User {
	v := ctx.Value(userCtxKey)
	if v == nil {
		return User{}
	}
	return v.(User)
}

func (s *APIServer) getRuntime() RuntimeConfig {
	s.runtimeMu.RLock()
	defer s.runtimeMu.RUnlock()
	return s.runtime
}
