package app

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxy-project/backend/internal/utils"
)

func (s *APIServer) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	writeJSON(w, http.StatusOK, "OK", "", map[string]interface{}{
		"id":          u.ID,
		"email":       u.Email,
		"appId":       u.AppID,
		"role":        u.Role,
		"status":      u.Status,
		"secretShown": u.SecretSeen,
	})
}

func (s *APIServer) handleSendResetCode(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	ip := s.clientIP(r)
	keys := []string{
		"secret_reset:user:" + strconv.FormatInt(u.ID, 10),
		"secret_reset:email:" + strings.ToLower(strings.TrimSpace(u.Email)),
		"secret_reset:ip:" + ip,
	}
	if err := s.ensureEmailSendAllowedMulti(keys, time.Minute); err != nil {
		writeJSON(w, http.StatusTooManyRequests, "EMAIL_RATE_LIMITED", err.Error(), nil)
		return
	}
	code := utils.RandCode(6)
	if err := s.storeEmailCode(u.Email, "secret_reset", code, 10*time.Minute); err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "store code failed", nil)
		return
	}
	if err := s.sendEmail(u.Email, "AniLink Proxy Secret 操作验证码", "验证码："+code+"，10分钟内有效。"); err != nil {
		log.Printf("smtp send secret reset code: %v", err)
		writeJSON(w, http.StatusInternalServerError, "SMTP_SEND_FAILED", "邮件发送失败，请稍后重试", nil)
		return
	}
	writeJSON(w, http.StatusOK, "OK", "sent", nil)
}

func (s *APIServer) handleRevealSecret(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	ip := s.clientIP(r)
	if !s.authRL.Allow("secret:reveal:user:"+strconv.FormatInt(u.ID, 10), EndpointLimit{RPS: 0.05, Burst: 2}) ||
		!s.authRL.Allow("secret:reveal:ip:"+ip, EndpointLimit{RPS: 0.1, Burst: 3}) {
		writeJSON(w, http.StatusTooManyRequests, "SECRET_RATE_LIMITED", "too many reveal attempts", nil)
		return
	}
	var stored string
	if err := s.db.QueryRow(`SELECT app_secret FROM users WHERE id=?`, u.ID).Scan(&stored); err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed", nil)
		return
	}
	plain, err := unsealAppSecret(stored, s.cfg.SecretWrapKey)
	if err != nil {
		log.Printf("unseal app secret (reveal user_id=%d): %v", u.ID, err)
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "secret unavailable", nil)
		return
	}
	_, _ = s.db.Exec(`UPDATE users SET secret_shown=1, updated_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), u.ID)
	writeJSON(w, http.StatusOK, "OK", "", map[string]string{"appSecret": plain})
}

func (s *APIServer) handleResetSecret(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	ip := s.clientIP(r)
	if !s.authRL.Allow("secret:reset:user:"+strconv.FormatInt(u.ID, 10), EndpointLimit{RPS: 0.03, Burst: 2}) ||
		!s.authRL.Allow("secret:reset:ip:"+ip, EndpointLimit{RPS: 0.08, Burst: 3}) {
		writeJSON(w, http.StatusTooManyRequests, "SECRET_RATE_LIMITED", "too many reset attempts", nil)
		return
	}
	var req struct {
		EmailCode string `json:"emailCode"`
	}
	if !decodeJSONStrict(w, r, &req) {
		return
	}
	ok, _ := s.verifyEmailCode(u.Email, "secret_reset", req.EmailCode)
	if !ok {
		writeJSON(w, http.StatusBadRequest, "EMAIL_CODE_INVALID", "email code invalid", nil)
		return
	}
	newSecret := utils.RandString(48)
	sealed, err := sealAppSecret(newSecret, s.cfg.SecretWrapKey)
	if err != nil {
		log.Printf("seal app secret (reset user_id=%d): %v", u.ID, err)
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "reset failed", nil)
		return
	}
	_, err = s.db.Exec(`UPDATE users SET app_secret=?, secret_shown=1, updated_at=? WHERE id=?`,
		sealed, time.Now().UTC().Format(time.RFC3339), u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "reset failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, "OK", "", map[string]string{"appSecret": newSecret})
}

func (s *APIServer) handleMyStats(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	if from == "" {
		from = time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	}
	if to == "" {
		to = time.Now().Format("2006-01-02")
	}
	rows, err := s.db.Query(`SELECT endpoint, SUM(total), SUM(success), SUM(auth_fail), SUM(rate_limited), SUM(upstream_fail), SUM(timeout), SUM(total_latency_ms)
		FROM app_metrics_daily WHERE app_id=? AND date>=? AND date<=?
		GROUP BY endpoint ORDER BY endpoint`, u.AppID, from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed", nil)
		return
	}
	defer rows.Close()
	type rowData struct {
		Endpoint     string  `json:"endpoint"`
		Total        int64   `json:"total"`
		Success      int64   `json:"success"`
		AuthFail     int64   `json:"authFail"`
		RateLimited  int64   `json:"rateLimited"`
		UpstreamFail int64   `json:"upstreamFail"`
		Timeout      int64   `json:"timeout"`
		AvgLatencyMs float64 `json:"avgLatencyMs"`
	}
	var out []rowData
	for rows.Next() {
		var d rowData
		var totalLatency int64
		if err := rows.Scan(&d.Endpoint, &d.Total, &d.Success, &d.AuthFail, &d.RateLimited, &d.UpstreamFail, &d.Timeout, &totalLatency); err == nil {
			if d.Total > 0 {
				d.AvgLatencyMs = float64(totalLatency) / float64(d.Total)
			}
			out = append(out, d)
		}
	}
	writeJSON(w, http.StatusOK, "OK", "", out)
}

func (s *APIServer) handleMyRisk(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r.Context())
	rows, err := s.db.Query(`SELECT level, rule_name, metric_value, detail, created_at FROM risk_events WHERE user_id=? ORDER BY id DESC LIMIT 100`, u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed", nil)
		return
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var level, rule, detail, created string
		var metric float64
		if err := rows.Scan(&level, &rule, &metric, &detail, &created); err == nil {
			out = append(out, map[string]interface{}{
				"level": level, "rule": rule, "metric": metric, "detail": detail, "createdAt": created,
			})
		}
	}
	writeJSON(w, http.StatusOK, "OK", "", out)
}
