package app

import (
	"database/sql"
	"os"
	"strings"
	"time"

	"proxy-project/backend/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

func initSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			app_id TEXT NOT NULL UNIQUE,
			app_secret TEXT NOT NULL,
			secret_shown INTEGER NOT NULL DEFAULT 0,
			role TEXT NOT NULL DEFAULT 'user',
			status TEXT NOT NULL DEFAULT 'active',
			ban_reason TEXT,
			ban_until TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS email_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			purpose TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			expire_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS email_send_rate (
			rate_key TEXT PRIMARY KEY,
			last_sent_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS email_code_attempts (
			rate_key TEXT PRIMARY KEY,
			fail_count INTEGER NOT NULL DEFAULT 0,
			lock_until TEXT,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS app_metrics_daily (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			date TEXT NOT NULL,
			total INTEGER NOT NULL DEFAULT 0,
			success INTEGER NOT NULL DEFAULT 0,
			auth_fail INTEGER NOT NULL DEFAULT 0,
			rate_limited INTEGER NOT NULL DEFAULT 0,
			upstream_fail INTEGER NOT NULL DEFAULT 0,
			timeout INTEGER NOT NULL DEFAULT 0,
			total_latency_ms INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			UNIQUE(app_id, endpoint, date)
		);`,
		`CREATE TABLE IF NOT EXISTS risk_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			level TEXT NOT NULL,
			rule_name TEXT NOT NULL,
			metric_value REAL NOT NULL,
			detail TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS system_config (
			k TEXT PRIMARY KEY,
			v TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_email_codes_email_purpose ON email_codes(email, purpose);`,
		`CREATE INDEX IF NOT EXISTS idx_users_appid ON users(app_id);`,
		`CREATE INDEX IF NOT EXISTS idx_risk_events_user ON risk_events(user_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_metrics_daily_date ON app_metrics_daily(date);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func ensureInitAdmin(db *sql.DB) error {
	email := os.Getenv("INIT_ADMIN_EMAIL")
	pass := os.Getenv("INIT_ADMIN_PASSWORD")
	if email == "" || pass == "" {
		return nil
	}
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(1) FROM users WHERE role='admin'`).Scan(&cnt); err != nil {
		return err
	}
	if cnt > 0 {
		return nil
	}
	// 仅在系统尚无 admin 时执行一次性引导创建。
	now := time.Now().UTC().Format(time.RFC3339)
	pwHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	appID := "adm_" + utils.RandString(24)
	secret := utils.RandString(48)
	_, err = db.Exec(`INSERT INTO users(email, password_hash, app_id, app_secret, secret_shown, role, status, created_at, updated_at)
		VALUES(?,?,?,?,1,'admin','active',?,?)`, strings.ToLower(email), string(pwHash), appID, secret, now, now)
	return err
}
