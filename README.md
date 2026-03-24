# AniLinkProxy

一个面向个人开发者的弹弹 Play API 代理网关：  
用户只需要向代理服务注册，即可获得独立 `AppId/AppSecret`，并以官方一致的签名方式调用接口。

## 核心功能

- 代理弹弹接口：`comment`、`search`、`bangumi`、`shin`、`match`、`match/batch`
- 客户端签名验签：`X-AppId` + `X-Timestamp` + `X-Signature`
- 账号系统：注册、登录、JWT 会话、密钥查看与重置
- 人机校验：Cloudflare Turnstile + 邮箱验证码
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
