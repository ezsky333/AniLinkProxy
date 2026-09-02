# AniLinkProxy

一个面向个人开发者的弹弹 Play API 代理网关：  
用户只需要向代理服务注册，即可获得独立 `AppId/AppSecret`，并以官方一致的签名方式调用接口。

## 核心功能

- 代理弹弹接口：`comment`、`search`、`bangumi`、`shin`、`match`、`match/batch`
- 客户端签名验签：`X-AppId` + `X-Timestamp` + `X-Signature`
- 账号系统：注册、登录、JWT 会话、密钥查看与重置
- 人机校验：邮箱验证码 + 可插拔验证码（Cloudflare Turnstile / 阿里云 ESA AI 验证码 / CaptchaLa，通过容器环境变量选择生效方）
- 风控能力：限流、并发锁、异常事件记录、自动封禁
- 运营能力：按 App 统计调用量、失败类型、延迟与风控事件
- 管理后台：用户封禁/解封、全局统计、运行时配置调整

## 设计目标

- 降低接入门槛：让个人用户也能稳定调用弹弹 API
- 降低上游压力：缓存 + 限流 + 校验 + 风控组合防滥用
- 低资源部署：Go + SQLite，适配轻量服务器场景

## 技术栈

- 后端：Go + Chi + SQLite
- 前端：Vue 3 + Vite + Vuetify
- 部署：Docker + GitHub Actions + GHCR

## 仓库结构

- `backend`：网关后端（根目录仅保留启动入口）
- `backend/internal/app`：后端核心业务代码（路由、代理、鉴权、风控、管理接口）
- `backend/internal/security`：签名算法相关
- `backend/internal/utils`：通用工具
- `frontend`：管理台前端

## 人机验证配置

人机验证用于登录与「发送注册验证码」等敏感操作，通过容器环境变量（Docker `--env` / `--env-file`）选择当前生效的验证码厂商：

| 环境变量 | 取值 | 说明 |
|---|---|---|
| `CAPTCHA_PROVIDER` | `turnstile` / `aliyun` / `captchala` / `none` | 生效的验证码厂商；留空或 `auto` 时按已配置凭据自动推断（优先 Turnstile） |

> 切换厂商后重启容器即可生效，无需修改业务代码。

### 1. Cloudflare Turnstile

```bash
CAPTCHA_PROVIDER=turnstile
TURNSTILE_SITE_KEY=你的SiteKey
TURNSTILE_SECRET_KEY=你的SecretKey
```

### 2. 阿里云 ESA AI 验证码 / 验证码 2.0

按 [阿里云官方快速上手](https://www.alibabacloud.com/help/zh/edge-security-acceleration/esa/user-guide/get-started-with-ai-captchas) 创建验证场景后，配置：

```bash
CAPTCHA_PROVIDER=aliyun
# 控制台右上角身份标 IDENTITY
ALIYUN_CAPTCHA_PREFIX=esa-q2*****cqb
# 验证场景归属地域：cn（中国内地）/ sgp（新加坡）
ALIYUN_CAPTCHA_REGION=cn
# 规则条目里的场景 ID
ALIYUN_CAPTCHA_SCENE_ID=你的SceneId
# 阿里云 AccessKey（RAM 子账号需授权 AliyunYundunAFSFullAccess）
ALIYUN_CAPTCHA_ACCESS_KEY_ID=你的AccessKeyId
ALIYUN_CAPTCHA_ACCESS_KEY_SECRET=你的AccessKeySecret
# 可选：自定义服务端验签 endpoint，默认按 region 推导（cn->captcha.cn-shanghai.aliyuncs.com）
# ALIYUN_CAPTCHA_ENDPOINT=captcha.cn-shanghai.aliyuncs.com
```

服务端验签走阿里云 `VerifyIntelligentCaptcha` OpenAPI（ACS3 签名，Go 原生实现，无需额外依赖）。

### 3. CaptchaLa

注册获取 App Key / App Secret（详见 [CaptchaLa 文档](https://docs.captcha.la/zh-CN/)）：

```bash
CAPTCHA_PROVIDER=captchala
CAPTCHALA_APP_KEY=你的AppKey
CAPTCHALA_APP_SECRET=你的AppSecret   # 仅服务端使用，切勿下发到浏览器
```

> 三个厂商共用同一前端配置接口 `/admin/api/auth/captcha/config`，后端据 `CAPTCHA_PROVIDER` 返回对应公共配置（不含机密），前端按提供方动态加载对应 SDK。
