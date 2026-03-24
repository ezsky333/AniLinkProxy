FROM alpine:3.21
WORKDIR /srv
RUN apk add --no-cache ca-certificates tzdata

# 运行时镜像仅负责承载构建产物：
# - build/proxy-server           (由 CI 预编译)
# - build/frontend-dist/*        (由 CI 预构建)
COPY build/proxy-server /srv/proxy-server
COPY build/frontend-dist /srv/frontend/dist

# Runtime envs (请在部署时通过 --env / --env-file 覆盖)
ENV PORT=8080 \
    FRONTEND_DIST=/srv/frontend/dist \
    SQLITE_PATH=/srv/data/proxy.db \
    UPSTREAM_BASE_URL=https://api.dandanplay.net \
    UPSTREAM_DANDAN_APP_ID= \
    UPSTREAM_DANDAN_APP_SECRET= \
    JWT_SECRET=change-this-in-production \
    SMTP_HOST= \
    SMTP_PORT=587 \
    SMTP_USERNAME= \
    SMTP_PASSWORD= \
    SMTP_FROM_ADDRESS= \
    TURNSTILE_SITE_KEY= \
    TURNSTILE_SECRET_KEY= \
    SECRET_WRAP_KEY= \
    AUTH_COOKIE_SECURE= \
    ADMIN_ALLOWED_ORIGIN= \
    INIT_ADMIN_EMAIL= \
    INIT_ADMIN_PASSWORD=

VOLUME ["/srv/data"]
EXPOSE 8080
ENTRYPOINT ["/srv/proxy-server"]
