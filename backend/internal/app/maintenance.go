package app

import (
	"log"
	"time"
)

// emailTablesCleanupLoop 定期清理过期验证码与陈旧频率记录，避免 SQLite 表无限增长。
func (s *APIServer) emailTablesCleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	run := func() {
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := s.db.Exec(`DELETE FROM email_codes WHERE expire_at < ?`, now); err != nil {
			log.Printf("email_codes cleanup: %v", err)
		}
		old := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
		if _, err := s.db.Exec(`DELETE FROM email_send_rate WHERE last_sent_at < ?`, old); err != nil {
			log.Printf("email_send_rate cleanup: %v", err)
		}
		if _, err := s.db.Exec(`DELETE FROM email_code_attempts WHERE updated_at < ?`, old); err != nil {
			log.Printf("email_code_attempts cleanup: %v", err)
		}
	}
	run()
	for range ticker.C {
		run()
	}
}
