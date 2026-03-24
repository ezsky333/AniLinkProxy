import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    // 使用本代理时，后端需设置 ADMIN_ALLOWED_ORIGIN=http://localhost:5175，否则 /admin/api 会因 CORS + Cookie 被拒绝。
    port: 5175,
    proxy: {
      "/api": "http://localhost:8080",
      "/admin/api": "http://localhost:8080"
    }
  }
});
