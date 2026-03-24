package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func loadConfig() (AppConfig, error) {
	port := getenv("PORT", "8080")
	smtpPort, _ := strconv.Atoi(getenv("SMTP_PORT", "587"))
	cfg := AppConfig{
		ListenAddr:         ":" + port,
		Upstream:           getenv("UPSTREAM_BASE_URL", "https://api.dandanplay.net"),
		UpstreamAppID:      os.Getenv("UPSTREAM_DANDAN_APP_ID"),
		UpstreamAppSecret:  os.Getenv("UPSTREAM_DANDAN_APP_SECRET"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
		SQLitePath:         getenv("SQLITE_PATH", "./data/proxy.db"),
		SMTPHost:           os.Getenv("SMTP_HOST"),
		SMTPPort:           smtpPort,
		SMTPUser:           os.Getenv("SMTP_USERNAME"),
		SMTPPass:           os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:           os.Getenv("SMTP_FROM_ADDRESS"),
		TurnstileSiteKey:   os.Getenv("TURNSTILE_SITE_KEY"),
		TurnstileSecretKey: os.Getenv("TURNSTILE_SECRET_KEY"),
		AdminAllowedOrigin: strings.TrimSpace(os.Getenv("ADMIN_ALLOWED_ORIGIN")),
		TrustedProxyCIDRs:  strings.TrimSpace(os.Getenv("TRUSTED_PROXY_CIDRS")),
	}
	if cfg.UpstreamAppID == "" || cfg.UpstreamAppSecret == "" {
		return cfg, errors.New("缺少 UPSTREAM_DANDAN_APP_ID / UPSTREAM_DANDAN_APP_SECRET")
	}
	if len(strings.TrimSpace(cfg.JWTSecret)) < 32 {
		return cfg, fmt.Errorf("JWT_SECRET 过短，生产环境请使用至少 32 位随机字符串")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SQLitePath), 0o755); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func defaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		TimestampCheckEnabled: true,
		TimestampToleranceSec: 300,
		CacheTTLMin: map[string]int{
			"comment": 30,
			"search":  180,
			"bangumi": 360,
			"shin":    360,
		},
		RateLimit: map[string]EndpointLimit{
			"comment":     {RPS: 6, Burst: 12},
			"search":      {RPS: 2, Burst: 4},
			"bangumi":     {RPS: 2, Burst: 4},
			"shin":        {RPS: 1, Burst: 2},
			"match":       {RPS: 0.3, Burst: 1},
			"match_batch": {RPS: 5, Burst: 5},
		},
		MatchLockTimeoutSec:  45,
		BodySizeLimitBytes:   1024 * 1024,
		UpstreamMaxBodyBytes: 4 * 1024 * 1024,
		BatchMaxItems:        30,
		CacheMaxEntries:      3000,
		CacheMaxBytes:        128 * 1024 * 1024,
		CacheMaxItemBytes:    256 * 1024,
		ReplayCacheSec:       600,
		AutoBanEnabled:       true,
		AutoBanMinutes:       30,
	}
}

func loadRuntimeConfig(db *sql.DB) (RuntimeConfig, error) {
	cfg := defaultRuntimeConfig()
	var raw string
	err := db.QueryRow(`SELECT v FROM system_config WHERE k='runtime_config'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		// 首次启动时将默认配置落库，后续以数据库中的运行时配置为准。
		if err := saveRuntimeConfig(db, cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return defaultRuntimeConfig(), nil
	}
	return normalizeRuntimeConfig(cfg), nil
}

func saveRuntimeConfig(db *sql.DB, cfg RuntimeConfig) error {
	cfg = normalizeRuntimeConfig(cfg)
	raw, _ := json.Marshal(cfg)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`INSERT INTO system_config(k, v, updated_at) VALUES('runtime_config', ?, ?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at`, string(raw), now)
	return err
}

func normalizeRuntimeConfig(cfg RuntimeConfig) RuntimeConfig {
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
	if cfg.MatchLockTimeoutSec <= 0 {
		cfg.MatchLockTimeoutSec = 45
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
	if cfg.CacheTTLMin == nil {
		cfg.CacheTTLMin = defaultRuntimeConfig().CacheTTLMin
	}
	if cfg.RateLimit == nil {
		cfg.RateLimit = defaultRuntimeConfig().RateLimit
	}
	return cfg
}
