package app

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

func (s *APIServer) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT id,email,app_id,role,status,ban_reason,ban_until,created_at FROM users ORDER BY id DESC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed", nil)
		return
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id int64
		var email, appID, role, status, created string
		var reason, until sql.NullString
		if err := rows.Scan(&id, &email, &appID, &role, &status, &reason, &until, &created); err == nil {
			out = append(out, map[string]interface{}{
				"id": id, "email": email, "appId": appID, "role": role, "status": status,
				"banReason": reason.String, "banUntil": until.String, "createdAt": created,
			})
		}
	}
	writeJSON(w, http.StatusOK, "OK", "", out)
}

func (s *APIServer) handleAdminBan(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	var req struct {
		Reason  string `json:"reason"`
		Minutes int    `json:"minutes"`
	}
	if !decodeJSONOptional(w, r, &req) {
		return
	}
	if req.Minutes <= 0 {
		req.Minutes = 60 * 24
	}
	now := time.Now().UTC().Format(time.RFC3339)
	until := time.Now().Add(time.Duration(req.Minutes) * time.Minute).UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`UPDATE users SET status='banned', ban_reason=?, ban_until=?, updated_at=? WHERE id=?`,
		req.Reason, until, now, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "ban failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, "OK", "banned", nil)
}

func (s *APIServer) handleAdminUnban(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	_, err := s.db.Exec(`UPDATE users SET status='active', ban_reason=NULL, ban_until=NULL, updated_at=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "unban failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, "OK", "unbanned", nil)
}

func (s *APIServer) handleAdminGlobalStats(w http.ResponseWriter, r *http.Request) {
	row := s.db.QueryRow(`SELECT SUM(total), SUM(success), SUM(auth_fail), SUM(rate_limited), SUM(upstream_fail), SUM(timeout) FROM app_metrics_daily`)
	var total, success, authFail, limited, upFail, timeout sql.NullInt64
	if err := row.Scan(&total, &success, &authFail, &limited, &upFail, &timeout); err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, "OK", "", map[string]interface{}{
		"total": total.Int64, "success": success.Int64, "authFail": authFail.Int64,
		"rateLimited": limited.Int64, "upstreamFail": upFail.Int64, "timeout": timeout.Int64,
	})
}

func (s *APIServer) handleAdminGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, "OK", "", s.getRuntime())
}

func (s *APIServer) handleAdminUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg RuntimeConfig
	if !decodeJSONStrict(w, r, &cfg) {
		return
	}
	if cfg.TimestampToleranceSec <= 0 {
		cfg.TimestampToleranceSec = 300
	}
	if cfg.BodySizeLimitBytes <= 0 {
		cfg.BodySizeLimitBytes = 1024 * 1024
	}
	if cfg.UpstreamMaxBodyBytes <= 0 {
		cfg.UpstreamMaxBodyBytes = 4 * 1024 * 1024
	}
	if cfg.BatchMaxItems <= 0 {
		cfg.BatchMaxItems = 30
	}
	if cfg.CacheMaxEntries <= 0 {
		cfg.CacheMaxEntries = 3000
	}
	if cfg.CacheMaxBytes <= 0 {
		cfg.CacheMaxBytes = 128 * 1024 * 1024
	}
	if cfg.CacheMaxItemBytes <= 0 {
		cfg.CacheMaxItemBytes = 256 * 1024
	}
	if cfg.ReplayCacheSec <= 0 {
		cfg.ReplayCacheSec = 600
	}
	if cfg.MatchLockTimeoutSec <= 0 {
		cfg.MatchLockTimeoutSec = 45
	}
	if err := saveRuntimeConfig(s.db, cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "save failed", nil)
		return
	}
	s.runtimeMu.Lock()
	s.runtime = cfg
	s.runtimeMu.Unlock()
	s.cache.Reconfigure(cfg.CacheMaxEntries, cfg.CacheMaxBytes, cfg.CacheMaxItemBytes)
	writeJSON(w, http.StatusOK, "OK", "updated", cfg)
}

func (s *APIServer) handleAdminAllUserStats(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
		SELECT u.id, u.email, u.app_id, u.role, u.status,
		       COALESCE(SUM(m.total), 0) as total,
		       COALESCE(SUM(m.success), 0) as success,
		       COALESCE(SUM(m.auth_fail), 0) as auth_fail,
		       COALESCE(SUM(m.rate_limited), 0) as rate_limited,
		       COALESCE(SUM(m.upstream_fail), 0) as upstream_fail,
		       COALESCE(SUM(m.timeout), 0) as timeout
		FROM users u
		LEFT JOIN app_metrics_daily m ON u.app_id = m.app_id
		GROUP BY u.id, u.email, u.app_id, u.role, u.status
		ORDER BY u.id DESC
	`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed", nil)
		return
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id int64
		var email, appID, role, status string
		var total, success, authFail, limited, upFail, timeout int64
		if err := rows.Scan(&id, &email, &appID, &role, &status, &total, &success, &authFail, &limited, &upFail, &timeout); err == nil {
			out = append(out, map[string]interface{}{
				"id": id, "email": email, "appId": appID, "role": role, "status": status,
				"total": total, "success": success, "authFail": authFail,
				"rateLimited": limited, "upstreamFail": upFail, "timeout": timeout,
			})
		}
	}
	writeJSON(w, http.StatusOK, "OK", "", out)
}

func (s *APIServer) handleAdminAllRiskEvents(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
		SELECT r.id, r.app_id, r.user_id, u.email, r.level, r.rule_name, r.metric_value, r.detail, r.created_at
		FROM risk_events r
		JOIN users u ON r.user_id = u.id
		ORDER BY r.created_at DESC
		LIMIT 1000
	`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed", nil)
		return
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id int64
		var appID string
		var userID int64
		var email, level, ruleName, detail, createdAt string
		var metricValue float64
		if err := rows.Scan(&id, &appID, &userID, &email, &level, &ruleName, &metricValue, &detail, &createdAt); err == nil {
			out = append(out, map[string]interface{}{
				"id": id, "appId": appID, "userId": userID, "email": email,
				"level": level, "ruleName": ruleName, "metricValue": metricValue,
				"detail": detail, "createdAt": createdAt,
			})
		}
	}
	writeJSON(w, http.StatusOK, "OK", "", out)
}
