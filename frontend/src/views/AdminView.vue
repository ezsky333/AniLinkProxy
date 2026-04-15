<template>
  <!-- 单根节点：避免 router-view + transition(mode=out-in) 在 Fragment 子组件上出现白屏 -->
  <div class="admin-view">
  <v-card class="mb-4" :loading="pageLoading">
    <v-card-title class="d-flex align-center flex-wrap">
      <span>超管控制台</span>
      <v-spacer />
      <v-btn color="primary" variant="tonal" :loading="pageLoading" @click="loadAll">刷新数据</v-btn>
    </v-card-title>
    <v-card-text>
      <v-alert v-if="pageError" type="error" variant="tonal" class="mb-3">{{ pageError }}</v-alert>
      <v-alert type="info" variant="tonal" class="mb-3">
        全局总请求: {{ global?.total || 0 }}，成功: {{ global?.success || 0 }}，鉴权失败: {{ global?.authFail || 0 }}，限流: {{ global?.rateLimited || 0 }}
      </v-alert>
      <v-expansion-panels>
        <v-expansion-panel title="运行参数">
          <v-expansion-panel-text>
            <v-text-field v-model.number="cfg.timestampToleranceSec" label="时间戳容忍秒数" />
            <v-text-field v-model.number="cfg.matchLockTimeoutSec" label="match锁超时秒数" />
            <v-text-field v-model.number="cfg.bodySizeLimitBytes" label="请求体大小限制" />
            <v-text-field v-model.number="cfg.batchMaxItems" label="批量match最大条数" />
            <v-switch v-model="cfg.timestampCheckEnabled" label="启用时间戳校验" color="primary" />
            <v-switch v-model="cfg.autoBanEnabled" label="启用自动封禁" color="primary" />
            <v-text-field v-model.number="cfg.autoBanMinutes" label="自动封禁时长(分钟)" />
            <v-btn color="primary" :loading="saveCfgLoading" @click="saveCfg">保存配置</v-btn>
          </v-expansion-panel-text>
        </v-expansion-panel>
      </v-expansion-panels>
    </v-card-text>
  </v-card>

  <v-card :loading="pageLoading">
    <v-card-title>账号管理</v-card-title>
    <v-card-text>
      <div v-if="!pageLoading && !pageError && users.length === 0" class="text-medium-emphasis text-body-2 py-4">暂无用户数据</div>
      <v-table v-else-if="users.length > 0" class="admin-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>邮箱</th>
            <th>AppId</th>
            <th>角色</th>
            <th>状态</th>
            <th>封禁到期</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td>{{ u.id }}</td>
            <td class="text-break">{{ u.email }}</td>
            <td>{{ u.appId }}</td>
            <td>{{ u.role }}</td>
            <td>{{ u.status }}</td>
            <td class="text-no-wrap">{{ u.banUntil }}</td>
            <td>
              <v-btn size="small" color="error" variant="tonal" class="mr-2 mb-1" @click="openBanDialog(u)">封禁</v-btn>
              <v-btn size="small" color="success" variant="tonal" class="mb-1" :loading="unbanLoadingId === u.id" @click="unban(u.id)">解封</v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

  <v-card :loading="pageLoading">
    <v-card-title>所有用户调用统计</v-card-title>
    <v-card-text>
      <div v-if="!pageLoading && !pageError && userStats.length === 0" class="text-medium-emphasis text-body-2 py-4">暂无统计数据</div>
      <v-table v-else-if="userStats.length > 0" class="admin-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>邮箱</th>
            <th>AppId</th>
            <th>角色</th>
            <th>状态</th>
            <th class="text-end">总请求</th>
            <th class="text-end">成功</th>
            <th class="text-end">鉴权失败</th>
            <th class="text-end">限流</th>
            <th class="text-end">上游失败</th>
            <th class="text-end">超时</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in userStats" :key="s.id">
            <td>{{ s.id }}</td>
            <td class="text-break">{{ s.email }}</td>
            <td>{{ s.appId }}</td>
            <td>{{ s.role }}</td>
            <td>{{ s.status }}</td>
            <td class="text-end">{{ s.total }}</td>
            <td class="text-end">{{ s.success }}</td>
            <td class="text-end">{{ s.authFail }}</td>
            <td class="text-end">{{ s.rateLimited }}</td>
            <td class="text-end">{{ s.upstreamFail }}</td>
            <td class="text-end">{{ s.timeout }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

  <v-card :loading="pageLoading">
    <v-card-title>所有用户风控记录</v-card-title>
    <v-card-text>
      <div v-if="!pageLoading && !pageError && riskEvents.length === 0" class="text-medium-emphasis text-body-2 py-4">暂无风控记录</div>
      <v-table v-else-if="riskEvents.length > 0" class="admin-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>邮箱</th>
            <th>AppId</th>
            <th>级别</th>
            <th>规则</th>
            <th>指标值</th>
            <th>详情</th>
            <th>时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in riskEvents" :key="r.id">
            <td>{{ r.id }}</td>
            <td class="text-break">{{ r.email }}</td>
            <td>{{ r.appId }}</td>
            <td>{{ r.level }}</td>
            <td>{{ r.ruleName }}</td>
            <td>{{ r.metricValue }}</td>
            <td class="text-break">{{ r.detail }}</td>
            <td class="text-no-wrap">{{ r.createdAt }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

  <v-dialog v-model="banDialog" max-width="420" persistent>
    <v-card>
      <v-card-title>确认封禁</v-card-title>
      <v-card-text>
        <p v-if="banTarget" class="mb-2">将对用户 <strong>{{ banTarget.email }}</strong> 执行封禁（默认 24 小时）。</p>
        <p class="text-body-2 text-medium-emphasis mb-0">封禁后对方将无法调用代理接口，请谨慎操作。</p>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="banDialog = false">取消</v-btn>
        <v-btn color="error" :loading="banLoading" @click="confirmBan">确认封禁</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
  </div>
</template>

<script setup>
import { ref } from "vue";
import { apiGet, apiPost, apiPut } from "../api";
import { showErrorSnackbar, showSuccessSnackbar } from "../snackbar";

const users = ref([]);
const global = ref({});
const cfg = ref({});
const userStats = ref([]);
const riskEvents = ref([]);
const pageLoading = ref(true);
const pageError = ref("");
const saveCfgLoading = ref(false);
const banDialog = ref(false);
const banTarget = ref(null);
const banLoading = ref(false);
const unbanLoadingId = ref(null);

async function loadAll() {
  pageLoading.value = true;
  pageError.value = "";
  try {
    const [u, g, c, s, r] = await Promise.all([
      apiGet("/admin/api/admin/users"),
      apiGet("/admin/api/admin/stats/global"),
      apiGet("/admin/api/admin/config"),
      apiGet("/admin/api/admin/stats/all-users"),
      apiGet("/admin/api/admin/risk/all-events")
    ]);
    users.value = u.data || [];
    global.value = g.data || {};
    cfg.value = c.data || {};
    userStats.value = s.data || [];
    riskEvents.value = r.data || [];
  } catch (e) {
    const msg = e?.response?.data?.message || e.message || "加载失败";
    pageError.value = msg;
    showErrorSnackbar(msg);
  } finally {
    pageLoading.value = false;
  }
}

function openBanDialog(u) {
  banTarget.value = u;
  banDialog.value = true;
}

async function confirmBan() {
  const id = banTarget.value?.id;
  if (id == null) return;
  banLoading.value = true;
  try {
    await apiPost(`/admin/api/admin/users/${id}/ban`, { reason: "manual ban", minutes: 1440 });
    showSuccessSnackbar("已封禁用户");
    banDialog.value = false;
    banTarget.value = null;
    await loadAll();
  } catch (e) {
    const msg = e?.response?.data?.message || e.message || "封禁失败";
    showErrorSnackbar(msg);
  } finally {
    banLoading.value = false;
  }
}

async function unban(id) {
  unbanLoadingId.value = id;
  try {
    await apiPost(`/admin/api/admin/users/${id}/unban`, {});
    showSuccessSnackbar("已解封");
    await loadAll();
  } catch (e) {
    const msg = e?.response?.data?.message || e.message || "解封失败";
    showErrorSnackbar(msg);
  } finally {
    unbanLoadingId.value = null;
  }
}

async function saveCfg() {
  saveCfgLoading.value = true;
  try {
    await apiPut("/admin/api/admin/config", cfg.value);
    showSuccessSnackbar("配置已保存");
    await loadAll();
  } catch (e) {
    const msg = e?.response?.data?.message || e.message || "保存失败";
    showErrorSnackbar(msg);
  } finally {
    saveCfgLoading.value = false;
  }
}

loadAll();
</script>

<style scoped>
.admin-view {
  width: 100%;
}
.admin-table {
  overflow-x: auto;
}
</style>
