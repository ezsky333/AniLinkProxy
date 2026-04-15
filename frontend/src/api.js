import axios from "axios";

const client = axios.create({
  baseURL: "/",
  timeout: 20000,
  withCredentials: true
});

export async function apiGet(url, params = {}) {
  const { data } = await client.get(url, { params });
  return data;
}

export async function apiPost(url, body = {}) {
  const { data } = await client.post(url, body);
  return data;
}

export async function apiPut(url, body = {}) {
  const { data } = await client.put(url, body);
  return data;
}

export async function apiAdminAllUserStats() {
  return apiGet("/admin/api/admin/stats/all-users");
}

export async function apiAdminAllRiskEvents() {
  return apiGet("/admin/api/admin/risk/all-events");
}
