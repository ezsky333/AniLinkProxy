package app

import (
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"proxy-project/backend/internal/utils"
)

func (s *APIServer) verifyTurnstile(token, remoteIP string) error {
	if s.cfg.TurnstileSecretKey == "" {
		return errors.New("turnstile not configured")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("turnstile token is required")
	}
	form := url.Values{}
	form.Set("secret", s.cfg.TurnstileSecretKey)
	form.Set("response", strings.TrimSpace(token))
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequest(http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("turnstile request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile verify failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Success bool     `json:"success"`
		Errors  []string `json:"error-codes"`
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("turnstile parse failed: %w", err)
	}
	if !result.Success {
		if len(result.Errors) > 0 {
			return fmt.Errorf("turnstile rejected: %s", strings.Join(result.Errors, ","))
		}
		return errors.New("turnstile rejected")
	}
	return nil
}

func (s *APIServer) ensureEmailSendAllowed(rateKey string, interval time.Duration) error {
	now := time.Now().UTC()
	var lastSent string
	err := s.db.QueryRow(`SELECT last_sent_at FROM email_send_rate WHERE rate_key=?`, rateKey).Scan(&lastSent)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.New("rate limit check failed")
	}
	if err == nil {
		if t, parseErr := time.Parse(time.RFC3339, lastSent); parseErr == nil {
			if wait := interval - now.Sub(t); wait > 0 {
				return fmt.Errorf("发送过于频繁，请 %d 秒后重试", int(wait.Seconds())+1)
			}
		}
		_, err = s.db.Exec(`UPDATE email_send_rate SET last_sent_at=? WHERE rate_key=?`, now.Format(time.RFC3339), rateKey)
		return err
	}
	_, err = s.db.Exec(`INSERT INTO email_send_rate(rate_key, last_sent_at) VALUES(?,?)`, rateKey, now.Format(time.RFC3339))
	return err
}

func (s *APIServer) ensureEmailSendAllowedMulti(rateKeys []string, interval time.Duration) error {
	if len(rateKeys) == 0 {
		return nil
	}
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("rate limit check failed")
	}
	defer tx.Rollback()
	for _, key := range rateKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		var lastSent string
		qErr := tx.QueryRow(`SELECT last_sent_at FROM email_send_rate WHERE rate_key=?`, key).Scan(&lastSent)
		if qErr != nil && !errors.Is(qErr, sql.ErrNoRows) {
			return errors.New("rate limit check failed")
		}
		if qErr == nil {
			if t, parseErr := time.Parse(time.RFC3339, lastSent); parseErr == nil {
				if wait := interval - now.Sub(t); wait > 0 {
					return fmt.Errorf("发送过于频繁，请 %d 秒后重试", int(wait.Seconds())+1)
				}
			}
		}
	}
	for _, key := range rateKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, upErr := tx.Exec(`INSERT INTO email_send_rate(rate_key, last_sent_at) VALUES(?,?) ON CONFLICT(rate_key) DO UPDATE SET last_sent_at=excluded.last_sent_at`, key, now.Format(time.RFC3339)); upErr != nil {
			return errors.New("rate limit write failed")
		}
	}
	return tx.Commit()
}

func (s *APIServer) storeEmailCode(email, purpose, code string, ttl time.Duration) error {
	now := time.Now().UTC()
	exp := now.Add(ttl)
	_, err := s.db.Exec(`INSERT INTO email_codes(email,purpose,code_hash,expire_at,created_at) VALUES(?,?,?,?,?)`, email, purpose, utils.ShaHex(strings.TrimSpace(code)), exp.Format(time.RFC3339), now.Format(time.RFC3339))
	return err
}
func (s *APIServer) verifyEmailCode(email, purpose, code string) (bool, error) {
	now := time.Now().UTC()
	rateKey := purpose + ":" + strings.ToLower(strings.TrimSpace(email))
	var failCount int
	var lockUntil sql.NullString
	_ = s.db.QueryRow(`SELECT fail_count, lock_until FROM email_code_attempts WHERE rate_key=?`, rateKey).Scan(&failCount, &lockUntil)
	if lockUntil.Valid {
		if t, err := time.Parse(time.RFC3339, lockUntil.String); err == nil && now.Before(t) {
			return false, errors.New("email code attempts exceeded")
		}
	}

	rows, err := s.db.Query(`SELECT id, code_hash, expire_at FROM email_codes WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 5`, email, purpose)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	target := utils.ShaHex(strings.TrimSpace(code))
	var okID int64
	for rows.Next() {
		var id int64
		var hash, exp string
		if err := rows.Scan(&id, &hash, &exp); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339, exp)
		if time.Now().After(t) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hash), []byte(target)) == 1 {
			okID = id
			break
		}
	}
	if okID == 0 {
		failCount++
		lock := sql.NullString{}
		if failCount >= 8 {
			lock = sql.NullString{
				String: now.Add(10 * time.Minute).Format(time.RFC3339),
				Valid:  true,
			}
		}
		var lockVal interface{}
		if lock.Valid {
			lockVal = lock.String
		}
		_, _ = s.db.Exec(`INSERT INTO email_code_attempts(rate_key, fail_count, lock_until, updated_at) VALUES(?,?,?,?)
			ON CONFLICT(rate_key) DO UPDATE SET fail_count=excluded.fail_count, lock_until=excluded.lock_until, updated_at=excluded.updated_at`,
			rateKey, failCount, lockVal, now.Format(time.RFC3339))
		return false, nil
	}
	_, _ = s.db.Exec(`DELETE FROM email_codes WHERE email=? AND purpose=?`, email, purpose)
	_, _ = s.db.Exec(`DELETE FROM email_code_attempts WHERE rate_key=?`, rateKey)
	return true, nil
}
func (s *APIServer) sendEmail(to, subject, body string) error {
	if s.cfg.SMTPHost == "" || s.cfg.SMTPUser == "" || s.cfg.SMTPPass == "" || s.cfg.SMTPFrom == "" {
		return errors.New("smtp not configured")
	}
	addr := net.JoinHostPort(s.cfg.SMTPHost, strconv.Itoa(s.cfg.SMTPPort))
	msg := "From: " + s.cfg.SMTPFrom + "\r\n" + "To: " + to + "\r\n" + "Subject: " + subject + "\r\n" + "MIME-Version: 1.0\r\n" + "Content-Type: text/plain; charset=UTF-8\r\n\r\n" + body + "\r\n"
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	tlsCfg := &tls.Config{ServerName: s.cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	if s.cfg.SMTPPort == 465 {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("smtp tls dial failed: %w", err)
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
		if err != nil {
			return fmt.Errorf("smtp client create failed: %w", err)
		}
		defer client.Quit()
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth failed: %w", err)
		}
		if err = client.Mail(s.cfg.SMTPFrom); err != nil {
			return fmt.Errorf("smtp mail from failed: %w", err)
		}
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("smtp rcpt failed: %w", err)
		}
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp data failed: %w", err)
		}
		if _, err = w.Write([]byte(msg)); err != nil {
			return fmt.Errorf("smtp write failed: %w", err)
		}
		if err = w.Close(); err != nil {
			return fmt.Errorf("smtp close failed: %w", err)
		}
		return nil
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("smtp dial failed: %w", err)
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp client create failed: %w", err)
	}
	defer client.Quit()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err = client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls failed: %w", err)
		}
	}
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth failed: %w", err)
	}
	if err = client.Mail(s.cfg.SMTPFrom); err != nil {
		return fmt.Errorf("smtp mail from failed: %w", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data failed: %w", err)
	}
	if _, err = w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write failed: %w", err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("smtp close failed: %w", err)
	}
	return nil
}
