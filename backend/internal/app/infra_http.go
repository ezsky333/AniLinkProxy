package app

import (
	"container/list"
	"math"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"
)

func newMemoryCache(maxEntries int, maxBytes int64, maxItemBytes int64) *MemoryCache {
	if maxEntries <= 0 {
		maxEntries = 3000
	}
	if maxBytes <= 0 {
		maxBytes = 128 * 1024 * 1024
	}
	if maxItemBytes <= 0 {
		maxItemBytes = 256 * 1024
	}
	return &MemoryCache{
		data:         map[string]cacheValue{},
		maxEntries:   maxEntries,
		maxBytes:     maxBytes,
		maxItemBytes: maxItemBytes,
		order:        list.New(),
		index:        map[string]*list.Element{},
	}
}

func (m *MemoryCache) Get(key string) ([]byte, bool) {
	m.mu.Lock()
	v, ok := m.data[key]
	if ok {
		if el := m.index[key]; el != nil {
			m.order.MoveToBack(el)
		}
	}
	m.mu.Unlock()
	if !ok || time.Now().After(v.ExpireAt) {
		return nil, false
	}
	return v.Value, true
}

func (m *MemoryCache) Set(key string, val []byte, ttl time.Duration) bool {
	size := int64(len(val))
	if size <= 0 || size > m.maxItemBytes {
		return false
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	if old, ok := m.data[key]; ok {
		m.currentBytes -= old.Size
	}
	m.data[key] = cacheValue{Value: val, ExpireAt: now.Add(ttl), Size: size}
	m.currentBytes += size
	if el := m.index[key]; el != nil {
		m.order.MoveToBack(el)
	} else {
		m.index[key] = m.order.PushBack(cacheOrderEntry{Key: key})
	}

	for len(m.data) > m.maxEntries || m.currentBytes > m.maxBytes {
		front := m.order.Front()
		if front == nil {
			break
		}
		entry, _ := front.Value.(cacheOrderEntry)
		m.removeByKey(entry.Key)
	}
	return true
}

func (m *MemoryCache) removeByKey(key string) {
	if el := m.index[key]; el != nil {
		m.order.Remove(el)
		delete(m.index, key)
	}
	if old, ok := m.data[key]; ok {
		m.currentBytes -= old.Size
		if m.currentBytes < 0 {
			m.currentBytes = 0
		}
		delete(m.data, key)
	}
}

func (m *MemoryCache) evictExpired(now time.Time) {
	for k, v := range m.data {
		if now.After(v.ExpireAt) {
			m.removeByKey(k)
		}
	}
}

func (m *MemoryCache) Reconfigure(maxEntries int, maxBytes int64, maxItemBytes int64) {
	if maxEntries <= 0 {
		maxEntries = 3000
	}
	if maxBytes <= 0 {
		maxBytes = 128 * 1024 * 1024
	}
	if maxItemBytes <= 0 {
		maxItemBytes = 256 * 1024
	}
	m.mu.Lock()
	m.maxEntries = maxEntries
	m.maxBytes = maxBytes
	m.maxItemBytes = maxItemBytes
	for len(m.data) > m.maxEntries || m.currentBytes > m.maxBytes {
		front := m.order.Front()
		if front == nil {
			break
		}
		entry, _ := front.Value.(cacheOrderEntry)
		m.removeByKey(entry.Key)
	}
	m.mu.Unlock()
}

func (m *MemoryCache) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		m.evictExpired(now)
		m.mu.Unlock()
	}
}

const (
	rateLimiterGCInterval   = 5 * time.Minute
	rateLimiterIdleTTL      = 20 * time.Minute
	rateLimiterMaxBuckets   = 10000
)

func newRateLimiter() *RateLimiter {
	now := time.Now()
	return &RateLimiter{buckets: map[string]*bucket{}, lastGC: now}
}

func (rl *RateLimiter) gcBuckets(now time.Time) {
	cutoff := now.Add(-rateLimiterIdleTTL)
	for k, b := range rl.buckets {
		if b.LastUsed.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}

func (rl *RateLimiter) Allow(key string, limit EndpointLimit) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	if len(rl.buckets) > rateLimiterMaxBuckets || now.Sub(rl.lastGC) > rateLimiterGCInterval {
		rl.gcBuckets(now)
		rl.lastGC = now
	}
	b, ok := rl.buckets[key]
	if !ok {
		// 首次请求按 burst 初始化，并立即消费 1 个令牌。
		rl.buckets[key] = &bucket{Tokens: limit.Burst - 1, LastRefill: now, LastUsed: now}
		return limit.Burst >= 1
	}
	// 令牌按经过时间 * RPS 回填，上限不超过 burst。
	elapsed := now.Sub(b.LastRefill).Seconds()
	b.Tokens = math.Min(limit.Burst, b.Tokens+elapsed*limit.RPS)
	b.LastRefill = now
	b.LastUsed = now
	if b.Tokens >= 1 {
		b.Tokens -= 1
		return true
	}
	return false
}

func (s *APIServer) adminCORSAllowOrigin(origin, host string) (allow string, ok bool) {
	if origin == "" {
		return "", true
	}
	static := strings.TrimSpace(s.cfg.AdminAllowedOrigin)
	if static != "" {
		if origin == static {
			return origin, true
		}
		return "", false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", false
	}
	if strings.EqualFold(u.Host, host) {
		return origin, true
	}
	return "", false
}

func (s *APIServer) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AppId, X-Timestamp, X-Signature")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		isAdminAPI := strings.HasPrefix(r.URL.Path, "/admin/api/")
		if isAdminAPI {
			allow, corsOK := s.adminCORSAllowOrigin(origin, r.Host)
			if allow != "" {
				w.Header().Set("Access-Control-Allow-Origin", allow)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}
			if !corsOK {
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) frontendHandler() http.Handler {
	dist := getenv("FRONTEND_DIST", filepath.Clean(filepath.Join(".", "..", "frontend", "dist")))
	distAbs, _ := filepath.Abs(dist)
	index := filepath.Join(dist, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/admin/api/") {
			writeJSON(w, http.StatusNotFound, "NOT_FOUND", "route not found", nil)
			return
		}
		cleanPath := pathpkg.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		cleanPath = strings.TrimPrefix(cleanPath, "/")
		target := filepath.Join(dist, filepath.FromSlash(cleanPath))
		targetAbs, _ := filepath.Abs(target)
		if distAbs != "" && targetAbs != "" {
			prefix := distAbs + string(filepath.Separator)
			if targetAbs != distAbs && !strings.HasPrefix(targetAbs, prefix) {
				writeJSON(w, http.StatusBadRequest, "BAD_PATH", "invalid path", nil)
				return
			}
		}
		if _, err := os.Stat(target); err == nil && !strings.HasSuffix(r.URL.Path, "/") {
			http.ServeFile(w, r, target)
			return
		}
		if _, err := os.Stat(index); err == nil {
			http.ServeFile(w, r, index)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("frontend not built yet"))
	})
}
