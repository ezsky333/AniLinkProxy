<template>
  <v-row justify="center">
    <v-col cols="12" sm="10" md="5">
      <v-card>
        <v-card-title>登录</v-card-title>
        <v-card-text>
          <v-form ref="formRef" @submit.prevent="submit">
            <v-text-field
              v-model="email"
              label="账号"
              type="text"
              autocomplete="username"
              :disabled="loading"
              :rules="[rules.required]"
            />
            <v-text-field
              v-model="password"
              label="密码"
              type="password"
              autocomplete="current-password"
              :disabled="loading"
              :rules="[rules.required]"
            />
            <div class="mb-3">
              <CaptchaWidget ref="captchaRef" @verified="onVerified" @expired="onExpired" @error="onCaptchaError" />
            </div>
            <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
            <v-btn color="primary" block type="submit" :loading="loading">登录</v-btn>
          </v-form>
          <v-btn class="mt-3" variant="text" block to="/register">去注册</v-btn>
        </v-card-text>
      </v-card>
    </v-col>
  </v-row>
</template>

<script setup>
import { ref } from "vue";
import { useRouter } from "vue-router";
import { apiPost } from "../api";
import CaptchaWidget from "../components/CaptchaWidget.vue";
import { setAuth } from "../auth";
import { showSuccessSnackbar } from "../snackbar";

const email = ref("");
const password = ref("");
const loading = ref(false);
const error = ref("");
const router = useRouter();
const captchaToken = ref("");
const captchaRef = ref(null);
const formRef = ref(null);

const rules = {
  required: (v) => (v != null && String(v).trim() !== "") || "请填写此项"
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

async function submit() {
  const { valid } = await formRef.value?.validate?.();
  if (valid === false) return;

  loading.value = true;
  error.value = "";
  try {
    if (!captchaToken.value) throw new Error("请先完成人机验证");
    const res = await apiPost("/admin/api/auth/login", {
      email: email.value,
      password: password.value,
      captchaToken: captchaToken.value
    });
    if (res.code !== "OK") throw new Error(res.message || res.code);
    setAuth(res.data);
    showSuccessSnackbar("登录成功");
    router.push("/");
  } catch (e) {
    error.value = e?.response?.data?.message || e.message || "登录失败";
  } finally {
    loading.value = false;
    captchaToken.value = "";
    captchaRef.value?.reset?.();
  }
}
</script>
