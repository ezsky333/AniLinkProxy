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

// aliyunCaptchaRegionEndpoint 返回验证码2.0/ESA AI 验证码服务端验签 endpoint。
// 境内 cn 对应 cn-shanghai，境外 sgp 对应 ap-southeast-1。
func aliyunCaptchaRegionEndpoint(region string) string {
	switch strings.ToLower(strings.TrimSpace(region)) {
	case "sgp", "singapore", "ap-southeast-1":
		return "captcha.ap-southeast-1.aliyuncs.com"
	default:
		return "captcha.cn-shanghai.aliyuncs.com"
	}
}

// captchaProvider 解析当前生效的人机验证提供商标识。
// 显式配置 CAPTCHA_PROVIDER 时优先；否则依据既有 Turnstile 密钥自动推断以保持向后兼容。
func (s *APIServer) captchaProvider() string {
	switch s.cfg.CaptchaProvider {
	case captchaProviderTurnstile, captchaProviderAliyun, captchaProviderCaptchaLa, captchaProviderNone:
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
	if s.cfg.AliyunCaptchaSceneID != "" && s.cfg.AliyunCaptchaPrefix != "" &&
		s.cfg.AliyunCaptchaAccessKeyID != "" && s.cfg.AliyunCaptchaAccessKeySecret != "" {
		return captchaProviderAliyun
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
	case captchaProviderAliyun:
		return s.cfg.AliyunCaptchaPrefix != "" && s.cfg.AliyunCaptchaSceneID != "" &&
			s.cfg.AliyunCaptchaAccessKeyID != "" && s.cfg.AliyunCaptchaAccessKeySecret != ""
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
	case captchaProviderAliyun:
		out["config"] = map[string]string{
			"region":  s.cfg.AliyunCaptchaRegion,
			"prefix":  s.cfg.AliyunCaptchaPrefix,
			"sceneId": s.cfg.AliyunCaptchaSceneID,
		}
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
	case captchaProviderAliyun:
		return s.verifyAliyunESA(token)
	case captchaProviderCaptchaLa:
		return s.verifyCaptchaLa(token, remoteIP)
	case captchaProviderNone:
		return errors.New("captcha not configured")
	default:
		return fmt.Errorf("unsupported captcha provider: %s", s.cfg.CaptchaProvider)
	}
}

// aliyunACS3Sign 生成阿里云 V3（ACS3-HMAC-SHA256）Authorization 头。
// host 需与 signedHeaders 中 host 一致；body 为原始表单体。
func aliyunACS3Sign(accessKeyID, accessKeySecret, host, action, version, nonce, date, body string) string {
	hashedPayload := sha256Hex(body)

	// RPC 风格请求体签名：规范化头仅含 host 与 x-acs-* 公共头（不含 content-type）。
	signedHeaders := []string{"host", "x-acs-action", "x-acs-content-sha256", "x-acs-date", "x-acs-signature-nonce", "x-acs-version"}
	headerValues := map[string]string{
		"host":                  host,
		"x-acs-action":          action,
		"x-acs-content-sha256":  hashedPayload,
		"x-acs-date":            date,
		"x-acs-signature-nonce": nonce,
		"x-acs-version":         version,
	}

	var canonHeaders strings.Builder
	for _, k := range signedHeaders {
		canonHeaders.WriteString(k + ":" + headerValues[k] + "\n")
	}

	canonicalRequest := "POST\n/\n\n" + canonHeaders.String() + "\n" + strings.Join(signedHeaders, ";") + "\n" + hashedPayload
	stringToSign := "ACS3-HMAC-SHA256\n" + sha256Hex(canonicalRequest)
	signature := hex.EncodeToString(hmacSHA256([]byte(accessKeySecret), stringToSign))

	return fmt.Sprintf("ACS3-HMAC-SHA256 Credential=%s,SignedHeaders=%s,Signature=%s",
		accessKeyID, strings.Join(signedHeaders, ";"), signature)
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)
}

// verifyAliyunESA 调用阿里云验证码2.0 VerifyIntelligentCaptcha 接口完成服务端验签。
// token 为前端 initAliyunCaptcha success 回调返回的 captchaVerifyParam（V3 架构）。
func (s *APIServer) verifyAliyunESA(token string) error {
	if !s.captchaConfigured() {
		return errors.New("aliyun captcha not configured")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("aliyun captcha token is required")
	}
	endpoint := strings.TrimSpace(s.cfg.AliyunCaptchaEndpoint)
	if endpoint == "" {
		endpoint = aliyunCaptchaRegionEndpoint(s.cfg.AliyunCaptchaRegion)
	}
	action := "VerifyIntelligentCaptcha"
	version := "2023-03-05"
	nonce := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().UnixMicro())
	date := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	form := url.Values{}
	form.Set("CaptchaVerifyParam", token)
	form.Set("SceneId", s.cfg.AliyunCaptchaSceneID)
	body := form.Encode()

	authorization := aliyunACS3Sign(s.cfg.AliyunCaptchaAccessKeyID, s.cfg.AliyunCaptchaAccessKeySecret,
		endpoint, action, version, nonce, date, body)

	req, err := http.NewRequest(http.MethodPost, "https://"+endpoint+"/", bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("aliyun captcha request failed: %w", err)
	}
	req.Host = endpoint
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", authorization)
	req.Header.Set("x-acs-action", action)
	req.Header.Set("x-acs-version", version)
	req.Header.Set("x-acs-date", date)
	req.Header.Set("x-acs-signature-nonce", nonce)
	req.Header.Set("x-acs-content-sha256", sha256Hex(body))

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("aliyun captcha verify failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var result struct {
		RequestID string `json:"RequestId"`
		Message   string `json:"Message"`
		Code      string `json:"Code"`
		Success   bool   `json:"Success"`
		Result    struct {
			VerifyResult bool   `json:"VerifyResult"`
			VerifyCode   string `json:"VerifyCode"`
		} `json:"Result"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("aliyun captcha parse failed: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("aliyun captcha request rejected: code=%s msg=%s", result.Code, result.Message)
	}
	if !result.Result.VerifyResult {
		return fmt.Errorf("aliyun captcha rejected: verifyCode=%s", result.Result.VerifyCode)
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
