package app

import (
	"container/list"
	"database/sql"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	roleUser  = "user"
	roleAdmin = "admin"

	// 人机验证提供商标识。
	captchaProviderTurnstile = "turnstile"
	captchaProviderGeetest   = "geetest"
	captchaProviderCaptchaLa = "captchala"
	captchaProviderNone      = "none"
)

type AppConfig struct {
	ListenAddr string
	Upstream   string

	UpstreamAppID     string
	UpstreamAppSecret string
	JWTSecret         string

	SQLitePath string

	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string

	TurnstileSiteKey   string
	TurnstileSecretKey string

	// CaptchaProvider 决定前端渲染的人机验证形态与后端验签方式，取值见 captchaProvider* 常量。
	CaptchaProvider string

	// 极验 GeeTest 行为验证4.0 相关配置。
	GeetestCaptchaID  string // 前端公开验证 id
	GeetestCaptchaKey string // 服务端密钥，切勿下发浏览器

	// CaptchaLa 智能验证码相关配置。
	CaptchaLaAppKey    string
	CaptchaLaAppSecret string

	AdminAllowedOrigin string
	TrustedProxyCIDRs  string

	// SecretWrapKey 为 32 字节 AES-GCM 密钥（建议 base64 置于 SECRET_WRAP_KEY）；为空则 AppSecret 明文落库（兼容旧数据）。
	SecretWrapKey []byte
	// AuthCookieSecure 为 true 时 Set-Cookie 带 Secure（HTTPS 生产环境应开启）。
	AuthCookieSecure bool
}

type RuntimeConfig struct {
	TimestampCheckEnabled bool                     `json:"timestampCheckEnabled"`
	TimestampToleranceSec int64                    `json:"timestampToleranceSec"`
	CacheTTLMin           map[string]int           `json:"cacheTtlMin"`
	RateLimit             map[string]EndpointLimit `json:"rateLimit"`
	MatchLockTimeoutSec   int                      `json:"matchLockTimeoutSec"`
	BodySizeLimitBytes    int64                    `json:"bodySizeLimitBytes"`
	UpstreamMaxBodyBytes  int64                    `json:"upstreamMaxBodyBytes"`
	BatchMaxItems         int                      `json:"batchMaxItems"`
	CacheMaxEntries       int                      `json:"cacheMaxEntries"`
	CacheMaxBytes         int64                    `json:"cacheMaxBytes"`
	CacheMaxItemBytes     int64                    `json:"cacheMaxItemBytes"`
	ReplayCacheSec        int64                    `json:"replayCacheSec"`
	AutoBanEnabled        bool                     `json:"autoBanEnabled"`
	AutoBanMinutes        int                      `json:"autoBanMinutes"`
}

type EndpointLimit struct {
	RPS   float64 `json:"rps"`
	Burst float64 `json:"burst"`
}

type User struct {
	ID                 int64
	Email              string
	Password           string
	AppID              string
	AppSecret          string
	SecretSeen         bool
	Role               string
	Status             string
	BanReason          sql.NullString
	BanUntil           sql.NullString
	CommentPushEnabled bool
	CreatedAt          string
}

type APIServer struct {
	cfg              AppConfig
	db               *sql.DB
	httpClient       *http.Client
	trustedProxyNets []*net.IPNet

	runtimeMu sync.RWMutex
	runtime   RuntimeConfig

	cache  *MemoryCache
	rl     *RateLimiter
	authRL *RateLimiter

	matchMu   sync.Mutex
	matchLock map[string]time.Time

	replayMu   sync.Mutex
	replaySeen map[string]time.Time

	metricCh chan metricEvent
	riskCh   chan riskEvent
}

type bucket struct {
	Tokens     float64
	LastRefill time.Time
	LastUsed   time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type cacheValue struct {
	Value    []byte
	ExpireAt time.Time
	Size     int64
}

type MemoryCache struct {
	mu           sync.RWMutex
	data         map[string]cacheValue
	maxEntries   int
	maxBytes     int64
	maxItemBytes int64
	currentBytes int64
	order        *list.List
	index        map[string]*list.Element
}

type cacheOrderEntry struct {
	Key string
}

type jsonResp struct {
	Code    string      `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type metricEvent struct {
	AppID      string
	Endpoint   string
	StatusCode string
	LatencyMS  int64
}

type riskEvent struct {
	User   User
	Level  string
	Rule   string
	Metric float64
	Detail string
}

type authClaims struct {
	UserID int64  `json:"uid"`
	Role   string `json:"role"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}
