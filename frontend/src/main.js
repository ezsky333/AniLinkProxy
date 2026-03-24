import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import { createVuetify } from "vuetify";
import * as components from "vuetify/components";
import * as directives from "vuetify/directives";
import "vuetify/styles";
import "@mdi/font/css/materialdesignicons.css";
import App from "./App.vue";
import { routes } from "./router";
import { authState, ensureSessionHydrated, syncAuthFromStorage } from "./auth";

const router = createRouter({
  history: createWebHistory(),
  routes
});

router.beforeEach(async (to) => {
  await ensureSessionHydrated();
  const authed = authState.isAuthed.value;
  if (!authed && to.path !== "/login" && to.path !== "/register") {
    return "/login";
  }
  if (to.meta.requiresAuth && !authed) return "/login";
  if (to.meta.adminOnly) {
    const role = authState.role.value;
    if (role !== "admin") return "/";
  }
  if (authed && (to.path === "/login" || to.path === "/register")) return "/";
  return true;
});

window.addEventListener("storage", syncAuthFromStorage);

const vuetify = createVuetify({
  components,
  directives
});
createApp(App).use(router).use(vuetify).mount("#app");
