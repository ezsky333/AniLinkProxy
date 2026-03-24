package app

import (
	"log"
	"strings"
	"time"
)

type metricAgg struct {
	AppID        string
	Endpoint     string
	Date         string
	Total        int64
	Success      int64
	AuthFail     int64
	RateLimited  int64
	UpstreamFail int64
	Timeout      int64
	TotalLatency int64
}

func (s *APIServer) metricsWriterLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	agg := make(map[string]*metricAgg)
	flush := func() {
		if len(agg) == 0 {
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		for _, m := range agg {
			_, err := s.db.Exec(`INSERT INTO app_metrics_daily(app_id, endpoint, date, total, success, auth_fail, rate_limited, upstream_fail, timeout, total_latency_ms, updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(app_id, endpoint, date) DO UPDATE SET
					total=total+excluded.total,
					success=success+excluded.success,
					auth_fail=auth_fail+excluded.auth_fail,
					rate_limited=rate_limited+excluded.rate_limited,
					upstream_fail=upstream_fail+excluded.upstream_fail,
					timeout=timeout+excluded.timeout,
					total_latency_ms=total_latency_ms+excluded.total_latency_ms,
					updated_at=excluded.updated_at`,
				m.AppID, m.Endpoint, m.Date, m.Total, m.Success, m.AuthFail, m.RateLimited, m.UpstreamFail, m.Timeout, m.TotalLatency, now)
			if err != nil {
				log.Printf("metrics flush error: %v", err)
			}
		}
		for k := range agg {
			delete(agg, k)
		}
	}

	for {
		select {
		case ev := <-s.metricCh:
			date := time.Now().Format("2006-01-02")
			key := ev.AppID + "|" + ev.Endpoint + "|" + date
			m := agg[key]
			if m == nil {
				m = &metricAgg{
					AppID:    ev.AppID,
					Endpoint: ev.Endpoint,
					Date:     date,
				}
				agg[key] = m
			}
			m.Total++
			m.TotalLatency += ev.LatencyMS
			switch ev.StatusCode {
			case "OK":
				m.Success++
			case "AUTH_SIGNATURE_INVALID", "AUTH_HEADER_MISSING", "AUTH_INVALID_APP", "AUTH_TIMESTAMP_INVALID", "AUTH_TIMESTAMP_EXPIRED", "AUTH_REPLAY_DETECTED":
				m.AuthFail++
			case "RATE_LIMITED", "MATCH_IN_FLIGHT":
				m.RateLimited++
			case "UPSTREAM_TIMEOUT":
				m.Timeout++
			default:
				if strings.Contains(ev.StatusCode, "UPSTREAM") {
					m.UpstreamFail++
				}
			}
			if len(agg) >= 256 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *APIServer) riskWriterLoop() {
	for ev := range s.riskCh {
		now := time.Now().UTC().Format(time.RFC3339)
		_, err := s.db.Exec(`INSERT INTO risk_events(app_id, user_id, level, rule_name, metric_value, detail, created_at) VALUES(?,?,?,?,?,?,?)`,
			ev.User.AppID, ev.User.ID, ev.Level, ev.Rule, ev.Metric, ev.Detail, now)
		if err != nil {
			log.Printf("risk write error: %v", err)
			continue
		}

		// auth_fail 常见于恶意构造请求，直接封号会被用于借刀封禁。
		if ev.Rule == "auth_fail" {
			continue
		}
		if !s.getRuntime().AutoBanEnabled || ev.Level != "high" {
			continue
		}
		banUntil := time.Now().Add(time.Duration(s.getRuntime().AutoBanMinutes) * time.Minute).UTC().Format(time.RFC3339)
		_, _ = s.db.Exec(`UPDATE users SET status='banned', ban_reason=?, ban_until=?, updated_at=? WHERE id=?`,
			"auto risk control ban", banUntil, now, ev.User.ID)
	}
}
