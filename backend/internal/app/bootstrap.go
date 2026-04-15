package app

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "modernc.org/sqlite"
)

// Run 启动服务入口，由 backend/main.go 调用。
func Run() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("配置读取失败: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.SQLitePath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatalf("数据库打开失败: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}
	// SQLite 单写者多读者场景：限制连接数，避免 1C1G 下过多并发写导致锁竞争与内存占用。
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err = initSchema(db); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}

	runtimeCfg, err := loadRuntimeConfig(db)
	if err != nil {
		log.Fatalf("运行时配置加载失败: %v", err)
	}

	if err = ensureInitAdmin(db, cfg); err != nil {
		log.Fatalf("初始超管创建失败: %v", err)
	}

	server := &APIServer{
		cfg: cfg,
		db:  db,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		runtime:          runtimeCfg,
		cache:            newMemoryCache(runtimeCfg.CacheMaxEntries, runtimeCfg.CacheMaxBytes, runtimeCfg.CacheMaxItemBytes),
		rl:               newRateLimiter(),
		authRL:           newRateLimiter(),
		matchLock:        map[string]time.Time{},
		replaySeen:       map[string]time.Time{},
		metricCh:         make(chan metricEvent, 4096),
		riskCh:           make(chan riskEvent, 2048),
		trustedProxyNets: parseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs),
	}
	// 启动后台维护协程：缓存过期清理 + match 锁兜底回收。
	go server.cache.gcLoop()
	go server.cleanupMatchLoop()
	go server.replayGCLoop()
	go server.metricsWriterLoop()
	go server.riskWriterLoop()
	go server.emailTablesCleanupLoop()

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(server.cors)

	registerRoutes(r, server)

	log.Printf("proxy service listening on %s", cfg.ListenAddr)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}
	if err = srv.ListenAndServe(); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

// registerRoutes 统一注册后台管理接口、代理接口和前端静态资源路由。
func registerRoutes(r chi.Router, server *APIServer) {
	r.Route("/admin/api", func(admin chi.Router) {
		admin.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, "OK", "running", map[string]string{"time": time.Now().Format(time.RFC3339)})
		})
		admin.Get("/auth/turnstile/site-key", server.handleTurnstileSiteKey)
		admin.Post("/auth/email/send-register", server.handleSendRegisterCode)
		admin.Post("/auth/register", server.handleRegister)
		admin.Post("/auth/login", server.handleLogin)
		admin.Post("/auth/logout", server.handleLogout)

		admin.Group(func(protected chi.Router) {
			protected.Use(server.authUserMiddleware)
			protected.Get("/me", server.handleMe)
			protected.Get("/stats/me", server.handleMyStats)
			protected.Get("/risk/me", server.handleMyRisk)
			protected.Post("/secret/send-reset-code", server.handleSendResetCode)
			protected.Post("/secret/reveal", server.handleRevealSecret)
			protected.Post("/secret/reset", server.handleResetSecret)
		})

		admin.Group(func(adm chi.Router) {
			adm.Use(server.authAdminMiddleware)
			adm.Get("/admin/users", server.handleAdminUsers)
			adm.Post("/admin/users/{userID}/ban", server.handleAdminBan)
			adm.Post("/admin/users/{userID}/unban", server.handleAdminUnban)
			adm.Get("/admin/stats/global", server.handleAdminGlobalStats)
			adm.Get("/admin/stats/all-users", server.handleAdminAllUserStats)
			adm.Get("/admin/risk/all-events", server.handleAdminAllRiskEvents)
			adm.Get("/admin/config", server.handleAdminGetConfig)
			adm.Put("/admin/config", server.handleAdminUpdateConfig)
		})
	})

	// Proxy routes
	r.Get("/api/v2/comment/{episodeId}", server.proxyGET)
	r.Get("/api/v2/search/episodes", server.proxyGET)
	r.Get("/api/v2/bangumi/{animeId}", server.proxyGET)
	r.Get("/api/v2/bangumi/shin", server.proxyGET)
	r.Post("/api/v2/match", server.proxyPOST)
	r.Post("/api/v2/match/batch", server.proxyPOST)

	// Frontend static files
	r.Handle("/*", server.frontendHandler())
}
