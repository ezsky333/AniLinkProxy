<template>
  <div class="captcha-widget">
    <v-skeleton-loader v-if="loading" type="image" class="rounded" height="65" />
    <template v-else>
      <!-- Cloudflare Turnstile -->
      <template v-if="provider === 'turnstile'">
        <div ref="turnstileBox"></div>
      </template>

      <!-- 阿里云 ESA AI 验证码 / 验证码2.0 -->
      <template v-else-if="provider === 'aliyun'">
        <div
          v-if="aliyunSuffix"
          :id="`aliyun-element-${aliyunSuffix}`"
          class="d-none"
        ></div>
        <v-btn
          ref="aliyunButton"
          block
          color="secondary"
          variant="tonal"
          :disabled="solved"
          :loading="aliyunLoading"
        >
          {{ solved ? "人机验证通过" : "点击完成人机验证" }}
        </v-btn>
        <v-alert
          v-if="aliyunError"
          type="error"
          variant="tonal"
          class="mt-2"
          density="compact"
        >
          {{ aliyunError }}
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
  else if (provider.value === "aliyun") resetAliyun();
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

// ---- 阿里云 ESA AI 验证码 ----
const aliyunButton = ref(null);
const aliyunError = ref("");
const aliyunLoading = ref(false);
const aliyunSuffix = ref("");
let aliyunInstance = null;

function loadAliyunScript() {
  return new Promise((resolve, reject) => {
    if (window.AliyunCaptcha && window.initAliyunCaptcha) return resolve();
    const existed = document.querySelector("script[data-captcha='aliyun']");
    if (existed) {
      existed.addEventListener("load", () => resolve(), { once: true });
      existed.addEventListener("error", () => reject(new Error("aliyun script load failed")), { once: true });
      return;
    }
    // 需在动态引入脚本前注入全局配置，SDK 会读取。
    window.AliyunCaptchaConfig = {
      region: cfg.value.region || "cn",
      prefix: cfg.value.prefix || ""
    };
    const script = document.createElement("script");
    script.src = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";
    script.async = true;
    script.defer = true;
    script.dataset.captcha = "aliyun";
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("aliyun script load failed"));
    document.head.appendChild(script);
  });
}

async function initAliyun() {
  if (aliyunLoading.value) return;
  aliyunError.value = "";
  aliyunLoading.value = true;
  try {
    await loadAliyunScript();
    await nextTick();
    const buttonSel = `#captcha-button-${aliyunSuffix.value}`;
    const elementSel = `#aliyun-element-${aliyunSuffix.value}`;
    window.initAliyunCaptcha({
      SceneId: cfg.value.sceneId,
      mode: "popup",
      element: elementSel,
      button: buttonSel,
      success: (captchaVerifyParam) => {
        solved.value = true;
        emit("verified", captchaVerifyParam);
      },
      fail: (result) => {
        solved.value = false;
        aliyunError.value = result?.msg || "阿里云验证未通过，请重试";
        emit("error", result);
      },
      getInstance: (instance) => {
        aliyunInstance = instance;
      }
    });
  } catch (e) {
    aliyunError.value = e?.message || "阿里云验证组件加载失败";
    emit("error", e);
  } finally {
    aliyunLoading.value = false;
  }
}

function resetAliyun() {
  aliyunInstance = null;
  aliyunError.value = "";
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
  } else if (provider.value === "aliyun") {
    await initAliyun();
  } else if (provider.value === "captchala") {
    await initCaptchaLa();
  }
}

onMounted(async () => {
  await loadConfig();
  // 等待验证组件区渲染后再进行针对 provider 的初始化。
  await nextTick();
  if (provider.value === "aliyun" && aliyunButton.value) {
    aliyunSuffix.value = `aliyun-${Math.random().toString(36).slice(2, 8)}`;
    aliyunButton.value.id = `captcha-button-${aliyunSuffix.value}`;
  }
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
