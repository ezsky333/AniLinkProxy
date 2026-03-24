import { computed, ref } from "vue";
import { apiGet, apiPost } from "./api";

const userRef = ref(null);
const sessionHydrated = ref(false);
let hydratePromise = null;

function parseUser(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function setAuth(data) {
  const user = data?.user ?? null;
  userRef.value = user;
  if (user) {
    localStorage.setItem("role", user.role || "");
    localStorage.setItem("user", JSON.stringify(user));
  } else {
    localStorage.removeItem("role");
    localStorage.removeItem("user");
  }
}

export function clearAuthLocal() {
  userRef.value = null;
  localStorage.removeItem("role");
  localStorage.removeItem("user");
}

export async function clearAuthServer() {
  try {
    await apiPost("/admin/api/auth/logout", {});
  } catch {
    // 网络错误时仍清理本地状态
  }
  clearAuthLocal();
}

export async function hydrateAuth() {
  try {
    const res = await apiGet("/admin/api/me");
    if (res.code === "OK" && res.data) {
      setAuth({ user: res.data });
      return;
    }
  } catch {
    /* 未登录或会话失效 */
  }
  clearAuthLocal();
}

export async function ensureSessionHydrated() {
  if (sessionHydrated.value) return;
  if (!hydratePromise) {
    hydratePromise = hydrateAuth().finally(() => {
      sessionHydrated.value = true;
    });
  }
  await hydratePromise;
}

export function syncAuthFromStorage() {
  userRef.value = parseUser(localStorage.getItem("user"));
}

export const authState = {
  user: userRef,
  role: computed(() => userRef.value?.role || ""),
  isAuthed: computed(() => Boolean(userRef.value?.id)),
  sessionHydrated
};
