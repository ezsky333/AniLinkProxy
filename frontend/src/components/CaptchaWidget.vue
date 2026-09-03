<template>
  <div class="captcha-widget">
    <v-skeleton-loader v-if="loading" type="image" class="rounded" height="65" />
    <template v-else>
      <!-- Cloudflare Turnstile -->
      <template v-if="provider === 'turnstile'">
        <div ref="turnstileBox"></div>
      </template>

      <!-- 极验 GeeTest 行为验证4.0（float：控件挂到容器） -->
      <template v-else-if="provider === 'geetest'">
        <div
          v-if="solved"
          class="geetest-solved-bar"
        >
          人机验证通过
        </div>
        <div
          v-else
          ref="geetestBox"
          :id="`geetest-box-${geetestKey}`"
          class="geetest-box"
        ></div>
        <v-alert
          v-if="geetestError"
          type="error"
          variant="tonal"
          class="mt-2"
          density="compact"
        >
          {{ geetestError }}
        </v-alert>
      </template>

      <!-- CaptchaLa 内嵌(embed)模式 -->
      <template v-else-if="provider === 'captchala'">
        <div
          ref="captchalaBox"
          :id="`captcha-la-${captchalaKey}`"
          class="captcha-la-box"
        ></div>
        <v-alert
          v-if="captchalaError"
          type="error"
          variant="tonal"
          class="mt-2"
          density="compact"
        >
          {{ captchalaError }}
        </v-alert>
      </template>

      <!-- 未配置 -->
      <v-alert v-else type="warning" variant="tonal">
        {{ unconfiguredText }}
      </v-alert>
    </template>
  </div>
</template>

<script setup>
import { nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { apiGet } from "../api";

const emit = defineEmits(["verified", "expired", "error"]);

const loading = ref(true);
const provider = ref("");
const enabled = ref(false);
const cfg = ref({});
const unconfiguredText = ref("人机验证未配置，请联系管理员。");

// --- 通用 ---
const solved = ref(false);

function reset() {
  solved.value = false;
  if (provider.value === "turnstile") resetTurnstile();
  else if (provider.value === "geetest") resetGeetest();
  else if (provider.value === "captchala") resetCaptchaLa();
}

defineExpose({ reset });

async function loadConfig() {
  loading.value = true;
  try {
    const res = await apiGet("/admin/api/auth/captcha/config");
    const d = res.data || {};
    provider.value = d.provider || "";
    enabled.value = !!d.enabled;
    cfg.value = d.config || {};
    if (d.note) unconfiguredText.value = d.note;
  } catch (e) {
    provider.value = "";
    enabled.value = false;
    unconfiguredText.value = e?.response?.data?.message || e?.message || "加载验证组件失败";
  } finally {
    loading.value = false;
  }
}

// ---- Cloudflare Turnstile ----
const turnstileBox = ref(null);
let turnstileWidgetId = null;

function loadTurnstileScript() {
  return new Promise((resolve, reject) => {
    if (window.turnstile) return resolve();
    const existed = document.querySelector("script[data-captcha='turnstile']");
    if (existed) {
      existed.addEventListener("load", () => resolve(), { once: true });
      existed.addEventListener("error", () => reject(new Error("turnstile script load failed")), { once: true });
      return;
    }
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.dataset.captcha = "turnstile";
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("turnstile script load failed"));
    document.head.appendChild(script);
  });
}

function renderTurnstile() {
  if (!window.turnstile || !turnstileBox.value || !cfg.value.siteKey) return;
  if (turnstileWidgetId !== null) {
    try {
      window.turnstile.remove(turnstileWidgetId);
    } catch {
      /* ignore */
    }
    turnstileWidgetId = null;
  }
  turnstileWidgetId = window.turnstile.render(turnstileBox.value, {
    sitekey: cfg.value.siteKey,
    callback: (token) => {
      solved.value = true;
      emit("verified", token);
    },
    "expired-callback": () => {
      solved.value = false;
      emit("expired");
    },
    "error-callback": () => {
      solved.value = false;
      emit("error", new Error("turnstile error"));
    }
  });
}

function resetTurnstile() {
  if (window.turnstile && turnstileWidgetId !== null) {
    try {
      window.turnstile.reset(turnstileWidgetId);
    } catch {
      /* ignore */
    }
  }
}

// ---- 极验 GeeTest 行为验证4.0（float，控件挂载到容器内） ----
const geetestBox = ref(null);
const geetestError = ref("");
const geetestKey = ref(0);
let geetestObj = null;
let geetestInited = false;

function loadGeetestScript() {
  return new Promise((resolve, reject) => {
    if (window.initGeetest4) return resolve();
    const existed = document.querySelector("script[data-captcha='geetest']");
    if (existed) {
      existed.addEventListener("load", () => resolve(), { once: true });
      existed.addEventListener("error", () => reject(new Error("geetest script load failed")), { once: true });
      return;
    }
    const script = document.createElement("script");
    script.src = "https://static.geetest.com/v4/gt4.js";
    script.async = true;
    script.defer = true;
    script.dataset.captcha = "geetest";
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("geetest script load failed"));
    document.head.appendChild(script);
  });
}

// 初始化一次并把验证控件 appendTo 到容器内（float 模式，验证码由用户点击容器内控件触发）。
async function initGeetest() {
  if (geetestInited) return;
  geetestError.value = "";
  try {
    await loadGeetestScript();
    await nextTick();
    if (!window.initGeetest4) throw new Error("Geetest SDK 不可用");
    const containerSel = `#geetest-box-${geetestKey.value}`;
    if (!document.querySelector(containerSel)) throw new Error("极验容器不存在");
    window.initGeetest4(
      {
        captchaId: cfg.value.captchaId,
        product: "float", // float：控件渲染到 appendTo 的容器，可验证
        protocol: "https://",
        language: "zho"
      },
      (captchaObj) => {
        geetestObj = captchaObj;
        captchaObj.appendTo(containerSel);
        captchaObj.onSuccess(() => {
          // 后端 geetest verifier 解析该 JSON。
          const validate = captchaObj.getValidate() || {};
          solved.value = true;
          emit("verified", JSON.stringify(validate));
        });
        captchaObj.onError((err) => {
          solved.value = false;
          geetestError.value = err?.msg || err?.message || "极验验证未通过，请重试";
          emit("error", err);
        });
        geetestInited = true;
      }
    );
  } catch (e) {
    geetestError.value = e?.message || "极验验证组件加载失败";
    emit("error", e);
  }
}

function resetGeetest() {
  solved.value = false;
  if (geetestObj && typeof geetestObj.reset === "function") {
    try {
      geetestObj.reset();
    } catch {
      /* ignore */
    }
  }
  geetestError.value = "";
}

// ---- CaptchaLa ----
const captchalaBox = ref(null);
const captchalaError = ref("");
const captchalaKey = ref(0);

function loadCaptchaLaScript() {
  return new Promise((resolve, reject) => {
    if (window.Captchala) return resolve();
    const existed = document.querySelector("script[data-captcha='captchala']");
    if (existed) {
      existed.addEventListener("load", () => resolve(), { once: true });
      existed.addEventListener("error", () => reject(new Error("captchala script load failed")), { once: true });
      return;
    }
    const script = document.createElement("script");
    script.src = "https://cdn.captcha-cdn.net/captchala.js";
    script.async = true;
    script.defer = true;
    script.dataset.captcha = "captchala";
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("captchala script load failed"));
    document.head.appendChild(script);
  });
}

// initCaptchaLa 采用 CaptchaLa 官方链式 API：init(...).onSuccess(...).appendTo('#container')。
async function initCaptchaLa() {
  captchalaError.value = "";
  try {
    await loadCaptchaLaScript();
    await nextTick();
    if (!window.Captchala) throw new Error("Captchala SDK 不可用");
    const containerSel = `#captcha-la-${captchalaKey.value}`;
    window.Captchala.init({
      appKey: cfg.value.appKey,
      product: "embed", // embed=内联勾选框+挑战；float/popup/bind 等其他模式需配合 bindTo/appendTo
      action: "default"
    })
      .onSuccess((res) => {
        solved.value = true;
        emit("verified", res?.token || res);
      })
      .onError((err) => {
        solved.value = false;
        captchalaError.value = err?.message || "CaptchaLa 验证未通过，请重试";
        emit("error", err);
      })
      .appendTo(containerSel);
  } catch (e) {
    captchalaError.value = e?.message || "CaptchaLa 验证组件加载失败";
    emit("error", e);
  }
}

// resetCaptchaLa 通过递增 key 让 Vue 重建全新容器，随后重新 init 挂载一次新的验证。
function resetCaptchaLa() {
  solved.value = false;
  captchalaKey.value += 1;
  captchalaError.value = "";
  nextTick(() => initCaptchaLa());
}

// ---- 生命周期 ----
async function renderByProvider() {
  if (!enabled.value) return;
  if (provider.value === "turnstile") {
    try {
      await loadTurnstileScript();
      await nextTick();
      renderTurnstile();
    } catch (e) {
      emit("error", e);
    }
  } else if (provider.value === "geetest") {
    // float 模式：挂载时初始化并把验证控件 appendTo 到容器。
    await initGeetest();
  } else if (provider.value === "captchala") {
    await initCaptchaLa();
  }
}

onMounted(async () => {
  await loadConfig();
  // 等待验证组件区渲染后再进行针对 provider 的初始化。
  await nextTick();
  await renderByProvider();
});

onBeforeUnmount(() => {
  if (window.turnstile && turnstileWidgetId !== null) {
    try {
      window.turnstile.remove(turnstileWidgetId);
    } catch {
      /* ignore */
    }
  }
});
</script>

<style scoped>
/* 极验 float 控件挂载区：给足空间、不裁剪，允许其内部浮层正常展示 */
.geetest-box {
  position: relative;
  min-height: 40px;
  overflow: visible;
  z-index: 10;
  display: flex;
  align-items: center;
}

.geetest-box :deep(.geetest_holder) {
  width: 100%;
}

.geetest-solved-bar {
  padding: 8px 12px;
  border: 1px solid rgba(76, 175, 80, 0.5);
  background: rgba(76, 175, 80, 0.08);
  color: #2e7d32;
  border-radius: 4px;
  text-align: center;
  font-size: 14px;
}
</style>
