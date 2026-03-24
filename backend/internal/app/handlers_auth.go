package app

import (
	"log"
	"net/http"
	"strings"
	"time"

	"proxy-project/backend/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

func (s *APIServer) handleTurnstileSiteKey(w http.ResponseWriter, r *http.Request) {
	if s.cfg.TurnstileSiteKey == "" {
		writeJSON(w, http.StatusOK, "OK", "", map[string]string{"siteKey": ""})
		return
	}
	writeJSON(w, http.StatusOK, "OK", "", map[string]string{"siteKey": s.cfg.TurnstileSiteKey})
}

func (s *APIServer) handleSendRegisterCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email          string `json:"email"`
		TurnstileToken string `json:"turnstileToken"`
	}
	if !decodeJSONStrict(w, r, &req) {
		return
	}
	if err := s.verifyTurnstile(req.TurnstileToken, s.clientIP(r)); err != nil {
		log.Printf("turnstile verify (register code): %v", err)
		writeJSON(w, http.StatusBadRequest, "TURNSTILE_INVALID", "人机验证失败，请重试", nil)
		return
	}
	if !strings.Contains(req.Email, "@") {
		writeJSON(w, http.StatusBadRequest, "EMAIL_INVALID", "invalid email", nil)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ip := s.clientIP(r)
	keys := []string{
		"register:email:" + email,
		"register:ip:" + ip,
		"register:ua:" + utils.ShortHash(strings.ToLower(strings.TrimSpace(r.UserAgent()))),
	}
	if err := s.ensureEmailSendAllowedMulti(keys, time.Minute); err != nil {
		writeJSON(w, http.StatusTooManyRequests, "EMAIL_RATE_LIMITED", err.Error(), nil)
		return
	}
	code := utils.RandCode(6)
	if err := s.storeEmailCode(email, "register", code, 10*time.Minute); err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "store code failed", nil)
		return
	}
	if err := s.sendEmail(email, "AniLink Proxy 注册验证码", "验证码："+code+"，10分钟内有效。"); err != nil {
		log.Printf("smtp send register code: %v", err)
		writeJSON(w, http.StatusInternalServerError, "SMTP_SEND_FAILED", "邮件发送失败，请稍后重试", nil)
		return
	}
	writeJSON(w, http.StatusOK, "OK", "sent", nil)
}

func (s *APIServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email     string `json:"email"`
		EmailCode string `json:"emailCode"`
		Password  string `json:"password"`
	}
	if !decodeJSONStrict(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, "PASSWORD_WEAK", "password length must >= 8", nil)
		return
	}
	ok, err := s.verifyEmailCode(email, "register", req.EmailCode)
	if err != nil || !ok {
		writeJSON(w, http.StatusBadRequest, "EMAIL_CODE_INVALID", "email code invalid", nil)
		return
	}
	pwHash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	now := time.Now().UTC().Format(time.RFC3339)
	appID := "app_" + utils.RandString(20)
	secret := utils.RandString(48)
	sealed, err := sealAppSecret(secret, s.cfg.SecretWrapKey)
	if err != nil {
		log.Printf("seal app secret (register): %v", err)
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "register failed", nil)
		return
	}
	_, err = s.db.Exec(`INSERT INTO users(email, password_hash, app_id, app_secret, role, status, secret_shown, created_at, updated_at)
		VALUES(?,?,?,?,?,?,0,?,?)`, email, string(pwHash), appID, sealed, roleUser, "active", now, now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, "REGISTER_FAILED", "email may already exists", nil)
		return
	}
	writeJSON(w, http.StatusOK, "OK", "register success", map[string]string{
		"appId":     appID,
		"appSecret": secret,
	})
}

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email          string `json:"email"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstileToken"`
	}
	if !decodeJSONStrict(w, r, &req) {
		return
	}
	ip := s.clientIP(r)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !s.authRL.Allow("login:ip:"+ip, EndpointLimit{RPS: 0.2, Burst: 6}) ||
		!s.authRL.Allow("login:email:"+email, EndpointLimit{RPS: 0.15, Burst: 4}) {
		writeJSON(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many login attempts", nil)
		return
	}
	if err := s.verifyTurnstile(req.TurnstileToken, ip); err != nil {
		log.Printf("turnstile verify (login): %v", err)
		writeJSON(w, http.StatusBadRequest, "TURNSTILE_INVALID", "人机验证失败，请重试", nil)
		return
	}
	var u User
	var secretShown int
	err := s.db.QueryRow(`SELECT id,email,password_hash,app_id,app_secret,secret_shown,role,status,ban_reason,ban_until,created_at FROM users WHERE email=?`,
		email).
		Scan(&u.ID, &u.Email, &u.Password, &u.AppID, &u.AppSecret, &secretShown, &u.Role, &u.Status, &u.BanReason, &u.BanUntil, &u.CreatedAt)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, "LOGIN_FAILED", "invalid credentials", nil)
		return
	}
	u.SecretSeen = secretShown == 1
	if accountBannedForHTTP(u) {
		writeJSON(w, http.StatusForbidden, "BANNED", "account banned", nil)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(req.Password)) != nil {
		// 密码错误会额外计入一次惩罚限流，抬高连续爆破成本。
		_ = s.authRL.Allow("login:penalty:ip:"+ip, EndpointLimit{RPS: 0.03, Burst: 1})
		writeJSON(w, http.StatusUnauthorized, "LOGIN_FAILED", "invalid credentials", nil)
		return
	}
	if _, err := unsealAppSecret(u.AppSecret, s.cfg.SecretWrapKey); err != nil {
		log.Printf("unseal app secret (login user_id=%d): %v", u.ID, err)
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "account data error", nil)
		return
	}
	token, err := s.makeJWT(u)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "token failed", nil)
		return
	}
	s.setAuthCookie(w, token)
	_, _ = s.db.Exec(`UPDATE users SET last_login_at=?, updated_at=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), u.ID)
	writeJSON(w, http.StatusOK, "OK", "", map[string]interface{}{
		"user": map[string]interface{}{
			"id":          u.ID,
			"email":       u.Email,
			"appId":       u.AppID,
			"role":        u.Role,
			"status":      u.Status,
			"secretShown": u.SecretSeen,
		},
	})
}

func (s *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearAuthCookie(w)
	writeJSON(w, http.StatusOK, "OK", "logged out", nil)
}
