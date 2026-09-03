package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// captchaProvider 解析当前生效的人机验证提供商标识。
// 显式配置 CAPTCHA_PROVIDER 时优先；否则依据既有凭据自动推断以保持向后兼容。
func (s *APIServer) captchaProvider() string {
	switch s.cfg.CaptchaProvider {
	case captchaProviderTurnstile, captchaProviderGeetest, captchaProviderCaptchaLa, captchaProviderNone:
		return s.cfg.CaptchaProvider
	case "auto", "":
		// fallthrough to inference
	default:
		return s.cfg.CaptchaProvider
	}
	// 自动推断：优先 Turnstile（历史默认），其次按已配置凭据匹配。
	if s.cfg.TurnstileSiteKey != "" || s.cfg.TurnstileSecretKey != "" {
		return captchaProviderTurnstile
	}
	if s.cfg.GeetestCaptchaID != "" && s.cfg.GeetestCaptchaKey != "" {
		return captchaProviderGeetest
	}
	if s.cfg.CaptchaLaAppKey != "" && s.cfg.CaptchaLaAppSecret != "" {
		return captchaProviderCaptchaLa
	}
	return captchaProviderNone
}

// captchaConfigured 判断当前验证码提供方是否具备完整配置（决定前端是否渲染验证组件）。
func (s *APIServer) captchaConfigured() bool {
	switch s.captchaProvider() {
	case captchaProviderTurnstile:
		return s.cfg.TurnstileSiteKey != "" && s.cfg.TurnstileSecretKey != ""
	case captchaProviderGeetest:
		return s.cfg.GeetestCaptchaID != "" && s.cfg.GeetestCaptchaKey != ""
	case captchaProviderCaptchaLa:
		return s.cfg.CaptchaLaAppKey != "" && s.cfg.CaptchaLaAppSecret != ""
	default:
		return false
	}
}

// captchaPublicConfig 返回下发到前端用于渲染验证组件的公共配置（不含任何服务端机密）。
func (s *APIServer) captchaPublicConfig() map[string]interface{} {
	provider := s.captchaProvider()
	out := map[string]interface{}{
		"provider": provider,
		"enabled":  s.captchaConfigured(),
	}
	switch provider {
	case captchaProviderTurnstile:
		out["config"] = map[string]string{"siteKey": s.cfg.TurnstileSiteKey}
	case captchaProviderGeetest:
		out["config"] = map[string]string{"captchaId": s.cfg.GeetestCaptchaID}
	case captchaProviderCaptchaLa:
		out["config"] = map[string]string{"appKey": s.cfg.CaptchaLaAppKey}
	case captchaProviderNone:
		out["config"] = map[string]string{}
	}
	return out
}

// handleCaptchaConfig 返回当前生效的人机验证提供方与其公共配置。
func (s *APIServer) handleCaptchaConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, "OK", "", s.captchaPublicConfig())
}

// captchaTokenFrom 兼容新老请求字段名读取验证令牌：
// 优先 captchaToken，其次 turnstileToken。
func captchaTokenFrom(v interface{ Get(key string) string }) string {
	if t := strings.TrimSpace(v.Get("captchaToken")); t != "" {
		return t
	}
	return strings.TrimSpace(v.Get("turnstileToken"))
}

// verifyCaptcha 按当前提供方执行服务端验签。token 为空或未配置时返回错误。
func (s *APIServer) verifyCaptcha(token, remoteIP string) error {
	switch s.captchaProvider() {
	case captchaProviderTurnstile:
		return s.verifyTurnstile(token, remoteIP)
	case captchaProviderGeetest:
		return s.verifyGeetest(token)
	case captchaProviderCaptchaLa:
		return s.verifyCaptchaLa(token, remoteIP)
	case captchaProviderNone:
		return errors.New("captcha not configured")
	default:
		return fmt.Errorf("unsupported captcha provider: %s", s.cfg.CaptchaProvider)
	}
}

// geetestValidateResult 为极验 v4 二次校验请求的前端参数。
// 前端将 captchaObj.getValidate() 的结果整体 JSON 化后放入 token。
type geetestValidateParams struct {
	LotNumber     string `json:"lot_number"`
	CaptchaOutput string `json:"captcha_output"`
	PassToken     string `json:"pass_token"`
	GenTime       string `json:"gen_time"`
}

// verifyGeetest 调用极验行为验证4.0 服务端二次校验接口。
// token 应为前端 getValidate() 结果的 JSON 字符串。
func (s *APIServer) verifyGeetest(token string) error {
	if !s.captchaConfigured() {
		return errors.New("geetest not configured")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("geetest token is required")
	}
	var p geetestValidateParams
	if err := json.Unmarshal([]byte(token), &p); err != nil {
		return errors.New("geetest validate param parse failed")
	}
	if strings.TrimSpace(p.LotNumber) == "" || strings.TrimSpace(p.CaptchaOutput) == "" ||
		strings.TrimSpace(p.PassToken) == "" || strings.TrimSpace(p.GenTime) == "" {
		return errors.New("geetest validate param incomplete")
	}

	// sign_token = HMAC-SHA256(key=captcha_key, message=lot_number)
	sign := hmac.New(sha256.New, []byte(s.cfg.GeetestCaptchaKey))
	_, _ = sign.Write([]byte(p.LotNumber))
	signToken := hex.EncodeToString(sign.Sum(nil))

	form := url.Values{}
	form.Set("lot_number", p.LotNumber)
	form.Set("captcha_output", p.CaptchaOutput)
	form.Set("pass_token", p.PassToken)
	form.Set("gen_time", p.GenTime)
	form.Set("sign_token", signToken)

	endpoint := "https://gcaptcha4.geetest.com/validate?captcha_id=" + url.QueryEscape(s.cfg.GeetestCaptchaID)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("geetest request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("geetest verify failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Status string `json:"status"`
		Result string `json:"result"`
		Reason string `json:"reason"`
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("geetest parse failed: %w", err)
	}
	if result.Status == "error" {
		return fmt.Errorf("geetest request error: %s", result.Reason)
	}
	if result.Result != "success" {
		return fmt.Errorf("geetest rejected: %s", result.Reason)
	}
	return nil
}

// verifyCaptchaLa 调用 CaptchaLa /v1/validate 完成服务端验签。
func (s *APIServer) verifyCaptchaLa(token, remoteIP string) error {
	if !s.captchaConfigured() {
		return errors.New("captchala not configured")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("captchala token is required")
	}
	payload := map[string]string{
		"pass_token": token,
	}
	if strings.TrimSpace(remoteIP) != "" {
		payload["client_ip"] = remoteIP
	}
	raw, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, "https://apiv1.captcha.la/v1/validate", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("captchala request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Key", s.cfg.CaptchaLaAppKey)
	req.Header.Set("X-App-Secret", s.cfg.CaptchaLaAppSecret)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("captchala verify failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Code int `json:"code"`
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("captchala parse failed: %w", err)
	}
	if result.Code != 0 || !result.Data.Valid {
		return fmt.Errorf("captchala rejected: code=%d", result.Code)
	}
	return nil
}
