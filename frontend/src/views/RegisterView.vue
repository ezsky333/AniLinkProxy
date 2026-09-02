<template>
  <v-row justify="center">
    <v-col cols="12" sm="10" md="6">
      <v-card>
        <v-card-title>注册（邮箱验证码 + 人机验证）</v-card-title>
        <v-card-text>
          <v-form ref="formRef" @submit.prevent="register">
            <v-text-field
              v-model="email"
              label="邮箱"
              type="email"
              autocomplete="email"
              :disabled="loading"
              :rules="[rules.required, rules.email]"
            />
            <v-text-field
              v-model="password"
              label="密码（至少8位）"
              type="password"
              autocomplete="new-password"
              :disabled="loading"
              :rules="[rules.required, rules.passwordMin]"
            />

            <div class="mb-3">
              <CaptchaWidget ref="captchaRef" @verified="onVerified" @expired="onExpired" @error="onCaptchaError" />
            </div>

            <div class="d-flex flex-column flex-sm-row align-stretch align-sm-center mb-2">
              <v-text-field
                v-model="emailCode"
                label="邮箱验证码"
                class="flex-grow-1 mb-2 mb-sm-0 mr-sm-3"
                :disabled="loading"
                :rules="[rules.required]"
                hide-details="auto"
              />
              <v-btn
                class="align-self-stretch"
                min-width="140"
                :disabled="codeCooldownSec > 0"
                :loading="sending"
                @click="sendCode"
              >
                {{ codeCooldownSec > 0 ? `${codeCooldownSec}s 后可重发` : "发送验证码" }}
              </v-btn>
            </div>
            <v-alert v-if="message" type="info" variant="tonal" class="mb-3">{{ message }}</v-alert>
            <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
            <v-btn color="primary" block type="submit" :loading="loading">注册</v-btn>
          </v-form>
          <v-btn class="mt-3" variant="text" block to="/login">返回登录</v-btn>
        </v-card-text>
      </v-card>
    </v-col>
  </v-row>
</template>

<script setup>
import { onUnmounted, ref } from "vue";
import { useRouter } from "vue-router";
import { apiPost } from "../api";
import CaptchaWidget from "../components/CaptchaWidget.vue";
import { showSuccessSnackbar } from "../snackbar";

const router = useRouter();
const email = ref("");
const password = ref("");
const emailCode = ref("");
const message = ref("");
const error = ref("");
const sending = ref(false);
const loading = ref(false);
const captchaToken = ref("");
const captchaRef = ref(null);
const formRef = ref(null);
const codeCooldownSec = ref(0);
let cooldownTimer = null;

const rules = {
  required: (v) => (v != null && String(v).trim() !== "") || "请填写此项",
  email: (v) => /.+@.+\..+/.test(String(v || "")) || "请输入有效邮箱",
  passwordMin: (v) => (String(v || "").length >= 8) || "密码至少 8 位"
};

function onVerified(token) {
  captchaToken.value = token;
}

function onExpired() {
  captchaToken.value = "";
}

function onCaptchaError() {
  captchaToken.value = "";
  error.value = "人机验证校验失败，请重试。";
}

function startCooldown(seconds = 60) {
  codeCooldownSec.value = seconds;
  if (cooldownTimer) clearInterval(cooldownTimer);
  cooldownTimer = setInterval(() => {
    codeCooldownSec.value -= 1;
    if (codeCooldownSec.value <= 0) {
      codeCooldownSec.value = 0;
      clearInterval(cooldownTimer);
      cooldownTimer = null;
    }
  }, 1000);
}

async function sendCode() {
  const emailRule = rules.email(email.value);
  if (emailRule !== true) {
    error.value = emailRule;
    await formRef.value?.validate?.();
    return;
  }
  sending.value = true;
  error.value = "";
  try {
    if (!captchaToken.value) throw new Error("请先完成人机验证");
    const res = await apiPost("/admin/api/auth/email/send-register", {
      email: email.value,
      captchaToken: captchaToken.value
    });
    if (res.code !== "OK") throw new Error(res.message || res.code);
    message.value = "邮箱验证码已发送，请查收邮件";
    showSuccessSnackbar("验证码已发送");
    startCooldown(60);
  } catch (e) {
    error.value = e?.response?.data?.message || e.message || "发送失败";
  } finally {
    sending.value = false;
    captchaToken.value = "";
    captchaRef.value?.reset?.();
  }
}

async function register() {
  const { valid } = await formRef.value?.validate?.();
  if (valid === false) return;

  loading.value = true;
  error.value = "";
  try {
    const res = await apiPost("/admin/api/auth/register", {
      email: email.value,
      emailCode: emailCode.value,
      password: password.value
    });
    if (res.code !== "OK") throw new Error(res.message || res.code);
    showSuccessSnackbar("注册成功，请登录");
    router.push("/login");
  } catch (e) {
    error.value = e?.response?.data?.message || e.message || "注册失败";
  } finally {
    loading.value = false;
  }
}

onUnmounted(() => {
  if (cooldownTimer) clearInterval(cooldownTimer);
});
</script>
