<template>
  <v-app>
    <v-app-bar color="primary" density="compact" v-if="isAuthed">
      <v-app-bar-title>AniLink Dandan Proxy 控制台</v-app-bar-title>
      <v-btn variant="text" to="/">首页</v-btn>
      <v-btn variant="text" to="/keys">我的密钥</v-btn>
      <v-btn variant="text" to="/stats">我的统计</v-btn>
      <v-btn variant="text" to="/risk">风控记录</v-btn>
      <v-btn v-if="role === 'admin'" variant="text" to="/admin">超管</v-btn>
      <v-spacer />
      <v-btn variant="text" @click="logout">退出</v-btn>
    </v-app-bar>
    <v-main>
      <v-container class="py-6">
        <router-view />
      </v-container>
    </v-main>
  </v-app>
</template>

<script setup>
import { useRouter } from "vue-router";
import { authState, clearAuthServer } from "./auth";

const router = useRouter();
const isAuthed = authState.isAuthed;
const role = authState.role;

async function logout() {
  await clearAuthServer();
  router.push("/login");
}
</script>
