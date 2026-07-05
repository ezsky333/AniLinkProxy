<template>
  <div class="admin-view">
    <v-card class="mb-4">
      <v-card-title class="d-flex align-center flex-wrap">
        <span>超管控制台</span>
        <v-spacer />
        <v-btn color="primary" variant="tonal" :loading="pageLoading" @click="loadAll">刷新数据</v-btn>
        <v-btn color="warning" variant="tonal" :loading="clearCacheLoading" @click="clearCache" class="ml-3">清除缓存</v-btn>
      </v-card-title>
    </v-card>

    <v-tabs v-model="tab" color="primary">
      <v-tab value="global">全局统计</v-tab>
      <v-tab value="user-stats">用户统计</v-tab>
      <v-tab value="users">账号管理</v-tab>
      <v-tab value="risk">风控记录</v-tab>
    </v-tabs>

    <v-window v-model="tab">
      <v-window-item value="global">
        <v-card :loading="pageLoading" class="mt-4">
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
      </v-window-item>

      <v-window-item value="user-stats">
        <v-card class="mt-4">
          <v-card-title>用户调用统计</v-card-title>
          <v-card-text>
            <v-row align="end">
              <v-col cols="12" sm="6" md="3">
                <v-select
                  v-model="selectedUser"
                  :items="users"
                  item-title="email"
                  item-value="id"
                  label="选择用户"
                  clearable
                  searchable
                  hide-details="auto"
                  @update:model-value="onUserChange"
                />
              </v-col>
              <v-col cols="12" sm="6" md="3">
                <v-date-input
                  v-model="fromDate"
                  label="开始日期"
                  density="comfortable"
                  hide-details="auto"
                  clearable
                  first-day-of-week="1"
                  name="anilink-admin-stats-from"
                  autocomplete="off"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </v-col>
              <v-col cols="12" sm="6" md="3">
                <v-date-input
                  v-model="toDate"
                  label="结束日期"
                  density="comfortable"
                  hide-details="auto"
                  clearable
                  first-day-of-week="1"
                  name="anilink-admin-stats-to"
                  autocomplete="off"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </v-col>
              <v-col cols="12" md="3">
                <v-btn color="primary" block class="mb-1" :loading="userStatsLoading" @click="loadUserStats">查询</v-btn>
              </v-col>
            </v-row>
            <v-alert v-if="userStatsError" type="error" variant="tonal" class="mb-4">{{ userStatsError }}</v-alert>
            <div v-if="!userStatsLoading && !userStatsError && userStatsRows.length === 0" class="text-medium-emphasis text-body-2 py-6 text-center">
              所选时间范围内暂无统计数据
            </div>
            <v-table v-else-if="userStatsRows.length > 0" class="stats-table">
              <thead>
                <tr>
                  <th>接口</th>
                  <th class="text-end">总请求</th>
                  <th class="text-end">成功</th>
                  <th class="text-end">鉴权失败</th>
                  <th class="text-end">限流</th>
                  <th class="text-end">上游失败</th>
                  <th class="text-end">超时</th>
                  <th class="text-end">平均延迟(ms)</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in userStatsRows" :key="item.endpoint">
                  <td class="text-break">{{ item.endpoint }}</td>
                  <td class="text-end">{{ item.total }}</td>
                  <td class="text-end">{{ item.success }}</td>
                  <td class="text-end">{{ item.authFail }}</td>
                  <td class="text-end">{{ item.rateLimited }}</td>
                  <td class="text-end">{{ item.upstreamFail }}</td>
                  <td class="text-end">{{ item.timeout }}</td>
                  <td class="text-end">{{ Math.round(item.avgLatencyMs || 0) }}</td>
                </tr>
              </tbody>
            </v-table>
          </v-card-text>
        </v-card>
      </v-window-item>

      <v-window-item value="users">
        <v-card :loading="pageLoading" class="mt-4">
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
      </v-window-item>

      <v-window-item value="risk">
        <v-card :loading="pageLoading" class="mt-4">
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
      </v-window-item>
    </v-window>

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

const tab = ref("global");
const users = ref([]);
const global = ref({});
const cfg = ref({});
const riskEvents = ref([]);
const pageLoading = ref(true);
const pageError = ref("");
const saveCfgLoading = ref(false);
const clearCacheLoading = ref(false);
const banDialog = ref(false);
const banTarget = ref(null);
const banLoading = ref(false);
const unbanLoadingId = ref(null);

// User stats
const selectedUser = ref(null);
const fromDate = ref(null);
const toDate = ref(null);
const userStatsRows = ref([]);
const userStatsLoading = ref(false);
const userStatsError = ref("");

function toYmdLocal(d) {
  if (d == null) return "";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return "";
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

async function loadAll() {
  pageLoading.value = true;
  pageError.value = "";
  try {
    const [u, g, c, r] = await Promise.all([
      apiGet("/admin/api/admin/users"),
      apiGet("/admin/api/admin/stats/global"),
      apiGet("/admin/api/admin/config"),
      apiGet("/admin/api/admin/risk/all-events")
    ]);
    users.value = u.data || [];
    global.value = g.data || {};
    cfg.value = c.data || {};
    riskEvents.value = r.data || [];
  } catch (e) {
    const msg = e?.response?.data?.message || e.message || "加载失败";
    pageError.value = msg;
    showErrorSnackbar(msg);
  } finally {
    pageLoading.value = false;
  }
}

function onUserChange() {
  if (selectedUser.value) {
    loadUserStats();
  } else {
    userStatsRows.value = [];
  }
}

async function loadUserStats() {
  if (!selectedUser.value) return;
  userStatsLoading.value = true;
  userStatsError.value = "";
  try {
    const from = toYmdLocal(fromDate.value);
    const to = toYmdLocal(toDate.value);
    const res = await apiGet(`/admin/api/admin/stats/user/${selectedUser.value}`, { from, to });
    userStatsRows.value = res.data || [];
  } catch (e) {
    const msg = e?.response?.data?.message || e.message || "加载失败";
    userStatsError.value = msg;
    showErrorSnackbar(msg);
  } finally {
    userStatsLoading.value = false;
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

async function clearCache() {
  clearCacheLoading.value = true;
  try {
    await apiPost("/admin/api/admin/cache/clear");
    showSuccessSnackbar("缓存已清除（响应缓存 + 重放防护缓存）");
  } catch (e) {
    const msg = e?.response?.data?.message || e.message || "清除失败";
    showErrorSnackbar(msg);
  } finally {
    clearCacheLoading.value = false;
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
