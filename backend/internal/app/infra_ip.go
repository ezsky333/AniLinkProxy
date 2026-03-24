package app

import (
	"net"
	"net/http"
	"strings"
	"time"
)

func parseTrustedProxyCIDRs(raw string) []*net.IPNet {
	out := make([]*net.IPNet, 0)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(part)
		if err != nil {
			continue
		}
		out = append(out, cidr)
	}
	return out
}

func (s *APIServer) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return host
	}
	if len(s.trustedProxyNets) == 0 || !isTrustedProxyIP(remoteIP, s.trustedProxyNets) {
		return remoteIP.String()
	}

	// 仅当请求来自可信代理时，才读取转发头，防止客户端伪造 XFF 绕过风控。
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
				return ip.String()
			}
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		if ip := net.ParseIP(xrip); ip != nil {
			return ip.String()
		}
	}
	return remoteIP.String()
}

func isTrustedProxyIP(ip net.IP, cidrs []*net.IPNet) bool {
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *APIServer) replayGCLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.replayMu.Lock()
		for k, exp := range s.replaySeen {
			if now.After(exp) {
				delete(s.replaySeen, k)
			}
		}
		s.replayMu.Unlock()
	}
}

func (s *APIServer) isReplayAndRemember(key string, ttlSec int64) bool {
	if ttlSec <= 0 {
		ttlSec = 600
	}
	now := time.Now()
	exp := now.Add(time.Duration(ttlSec) * time.Second)
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if v, ok := s.replaySeen[key]; ok && now.Before(v) {
		return true
	}
	s.replaySeen[key] = exp
	return false
}
