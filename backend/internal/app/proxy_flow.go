package app

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-project/backend/internal/security"
)

func (s *APIServer) proxyGET(w http.ResponseWriter, r *http.Request)  { s.proxyRequest(w, r, true) }
func (s *APIServer) proxyPOST(w http.ResponseWriter, r *http.Request) { s.proxyRequest(w, r, false) }

func (s *APIServer) proxyRequest(w http.ResponseWriter, r *http.Request, canCache bool) {
	start := time.Now()
	path := r.URL.Path
	endpoint := endpointKey(path)
	if endpoint == "" {
		writeJSON(w, http.StatusNotFound, "NOT_PROXY_ENDPOINT", "unsupported endpoint", nil)
		return
	}
	user, code, msg := s.verifyClientSignature(r)
	if code != "" {
		writeJSON(w, statusForCode(code), code, msg, nil)
		s.recordMetric("", endpoint, start, code)
		return
	}
	limit := s.getRateLimit(endpoint)
	if !s.rl.Allow(user.AppID+":"+endpoint, limit) {
		writeJSON(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
		s.recordMetric(user.AppID, endpoint, start, "RATE_LIMITED")
		s.createRiskEvent(user, "medium", "ratelimit", 1, "触发接口限流")
		return
	}
	releaseMatch := func() {}
	if endpoint == "match" || endpoint == "match_batch" {
		var ok bool
		// match 与 match_batch 共享同一个 app 级别并发锁，避免并发洪峰。
		ok, releaseMatch = s.tryAcquireMatchLock(user.AppID)
		if !ok {
			writeJSON(w, http.StatusTooManyRequests, "MATCH_IN_FLIGHT", "match request is already running", nil)
			s.recordMetric(user.AppID, endpoint, start, "RATE_LIMITED")
			return
		}
		defer releaseMatch()
	}
	var body []byte
	var err error
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, s.getRuntime().BodySizeLimitBytes))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, "BODY_TOO_LARGE", "request body exceeds limit", nil)
			s.recordMetric(user.AppID, endpoint, start, "VALIDATION_FAILED")
			return
		}
		if endpoint == "match" || endpoint == "match_batch" {
			if code, msg := s.validateMatchPayload(endpoint, body); code != "" {
				writeJSON(w, http.StatusBadRequest, code, msg, nil)
				s.recordMetric(user.AppID, endpoint, start, "VALIDATION_FAILED")
				s.createRiskEvent(user, "low", "payload_invalid", 1, msg)
				return
			}
		}
	}
	cacheKey := ""
	if canCache && isCacheableEndpoint(endpoint) {
		cacheKey = cacheKeyOf(r.URL.Path, r.URL.Query())
		if hit, ok := s.cache.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(hit)
			s.recordMetric(user.AppID, endpoint, start, "OK")
			return
		}
	}
	upstreamURL := s.cfg.Upstream + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request creation failed", nil)
		s.recordMetric(user.AppID, endpoint, start, "INTERNAL_ERROR")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	s.attachUpstreamSignature(req, path)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, "UPSTREAM_FAILED", err.Error(), nil)
		s.recordMetric(user.AppID, endpoint, start, "UPSTREAM_FAILED")
		s.createRiskEvent(user, "medium", "upstream_error", 1, err.Error())
		return
	}
	defer resp.Body.Close()
	maxRespBytes := s.getRuntime().UpstreamMaxBodyBytes
	if maxRespBytes <= 0 {
		maxRespBytes = 4 * 1024 * 1024
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes+1))
	if int64(len(respBody)) > maxRespBytes {
		writeJSON(w, http.StatusBadGateway, "UPSTREAM_RESPONSE_TOO_LARGE", "upstream response too large", nil)
		s.recordMetric(user.AppID, endpoint, start, "UPSTREAM_FAILED")
		s.createRiskEvent(user, "medium", "upstream_response_too_large", 1, "上游响应超过限制")
		return
	}
	if cacheKey != "" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		ttl := time.Duration(s.getTTL(endpoint)) * time.Minute
		_ = s.cache.Set(cacheKey, respBody, ttl)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.recordMetric(user.AppID, endpoint, start, "OK")
	} else {
		s.recordMetric(user.AppID, endpoint, start, "UPSTREAM_FAILED")
	}
}

func (s *APIServer) verifyClientSignature(r *http.Request) (User, string, string) {
	appID, ts, sign := r.Header.Get("X-AppId"), r.Header.Get("X-Timestamp"), r.Header.Get("X-Signature")
	if appID == "" || ts == "" || sign == "" {
		return User{}, "AUTH_HEADER_MISSING", "missing signature headers"
	}
	user, err := s.findUserByAppID(appID)
	if err != nil {
		return User{}, "AUTH_INVALID_APP", "app id not found"
	}
	if user.Status == "banned" {
		if !user.BanUntil.Valid {
			return User{}, "BANNED", "account banned"
		}
		t, parseErr := time.Parse(time.RFC3339, user.BanUntil.String)
		if parseErr == nil && t.After(time.Now()) {
			return User{}, "BANNED", "account banned"
		}
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return User{}, "AUTH_TIMESTAMP_INVALID", "timestamp invalid"
	}
	rt := s.getRuntime()
	if rt.TimestampCheckEnabled {
		// 时间窗校验用于拦截重放请求，容忍范围由运行时配置控制。
		diff := time.Now().Unix() - tsInt
		if diff < 0 {
			diff = -diff
		}
		if diff > rt.TimestampToleranceSec {
			return User{}, "AUTH_TIMESTAMP_EXPIRED", "timestamp outside tolerance window"
		}
	}
	expected := security.GenerateSignature(appID, tsInt, r.URL.Path, user.AppSecret)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sign)) != 1 {
		s.createRiskEvent(user, "high", "auth_fail", 1, "签名验签失败")
		return User{}, "AUTH_SIGNATURE_INVALID", "signature invalid"
	}
	replayKey := appID + ":" + strconv.FormatInt(tsInt, 10) + ":" + sign + ":" + r.URL.Path
	if s.isReplayAndRemember(replayKey, rt.ReplayCacheSec) {
		s.createRiskEvent(user, "medium", "replay_attack", 1, "重复签名请求被拦截")
		return User{}, "AUTH_REPLAY_DETECTED", "replay detected"
	}
	return user, "", ""
}

func (s *APIServer) attachUpstreamSignature(req *http.Request, path string) {
	ts := time.Now().Unix()
	req.Header.Set("X-AppId", s.cfg.UpstreamAppID)
	req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Signature", security.GenerateSignature(s.cfg.UpstreamAppID, ts, path, s.cfg.UpstreamAppSecret))
}

func endpointKey(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/v2/comment/"):
		return "comment"
	case path == "/api/v2/search/episodes":
		return "search"
	case strings.HasPrefix(path, "/api/v2/bangumi/shin"):
		return "shin"
	case strings.HasPrefix(path, "/api/v2/bangumi/"):
		return "bangumi"
	case path == "/api/v2/match":
		return "match"
	case path == "/api/v2/match/batch":
		return "match_batch"
	default:
		return ""
	}
}

func isCacheableEndpoint(endpoint string) bool {
	return endpoint == "comment" || endpoint == "search" || endpoint == "bangumi" || endpoint == "shin"
}
func cacheKeyOf(path string, q map[string][]string) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(path)
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			b.WriteString("|")
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(v)
		}
	}
	return b.String()
}
func (s *APIServer) getTTL(endpoint string) int {
	if v, ok := s.getRuntime().CacheTTLMin[endpoint]; ok {
		return v
	}
	return 30
}
func (s *APIServer) getRateLimit(endpoint string) EndpointLimit {
	if v, ok := s.getRuntime().RateLimit[endpoint]; ok {
		return v
	}
	return EndpointLimit{RPS: 1, Burst: 2}
}

func (s *APIServer) validateMatchPayload(endpoint string, body []byte) (string, string) {
	if len(body) == 0 {
		return "PAYLOAD_INVALID", "body is empty"
	}
	if endpoint == "match" {
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			return "PAYLOAD_INVALID", "invalid json body"
		}
		if _, ok := req["matchMode"]; !ok {
			req["matchMode"] = "hashAndFileName"
		}
		mode, _ := req["matchMode"].(string)
		if mode != "hashAndFileName" && mode != "hashOnly" && mode != "fileNameOnly" {
			return "PAYLOAD_INVALID", "unsupported matchMode"
		}
	} else {
		var req struct {
			Requests []map[string]interface{} `json:"requests"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return "PAYLOAD_INVALID", "invalid json body"
		}
		if len(req.Requests) == 0 {
			return "PAYLOAD_INVALID", "requests must not be empty"
		}
		if len(req.Requests) > s.getRuntime().BatchMaxItems {
			return "PAYLOAD_INVALID", "batch request exceeds max items"
		}
	}
	return "", ""
}

func (s *APIServer) tryAcquireMatchLock(appID string) (bool, func()) {
	s.matchMu.Lock()
	defer s.matchMu.Unlock()
	if _, exists := s.matchLock[appID]; exists {
		return false, func() {}
	}
	s.matchLock[appID] = time.Now().Add(time.Duration(s.getRuntime().MatchLockTimeoutSec) * time.Second)
	return true, func() { s.matchMu.Lock(); delete(s.matchLock, appID); s.matchMu.Unlock() }
}
func (s *APIServer) cleanupMatchLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.matchMu.Lock()
		for appID, exp := range s.matchLock {
			if now.After(exp) {
				delete(s.matchLock, appID)
			}
		}
		s.matchMu.Unlock()
	}
}
func (s *APIServer) recordMetric(appID, endpoint string, start time.Time, statusCode string) {
	if appID == "" {
		return
	}
	ev := metricEvent{
		AppID:      appID,
		Endpoint:   endpoint,
		StatusCode: statusCode,
		LatencyMS:  time.Since(start).Milliseconds(),
	}
	select {
	case s.metricCh <- ev:
	default:
		log.Printf("metric queue is full, dropping metric for %s:%s", appID, endpoint)
	}
}
func (s *APIServer) createRiskEvent(user User, level, rule string, metric float64, detail string) {
	ev := riskEvent{
		User:   user,
		Level:  level,
		Rule:   rule,
		Metric: metric,
		Detail: detail,
	}
	select {
	case s.riskCh <- ev:
	default:
		log.Printf("risk queue is full, dropping risk event for user=%d rule=%s", user.ID, rule)
	}
}
