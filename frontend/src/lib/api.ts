"use client";

const TOKEN_KEY = "sentinel_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY);
}

export class AuthError extends Error {}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`/api${path}`, { ...options, headers });
  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new AuthError("unauthenticated");
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  async login(username: string, password: string): Promise<string> {
    const form = new URLSearchParams({ username, password });
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    if (!res.ok) throw new Error("Invalid credentials");
    const data = await res.json();
    setToken(data.access_token);
    return data.access_token;
  },
  overview: () => request<any>("/dashboard/overview"),
  incidents: (status?: string) =>
    request<any[]>(`/incidents${status ? `?status=${status}` : ""}`),
  incident: (id: number) => request<any>(`/incidents/${id}`),
  setIncidentStatus: (id: number, status: string) =>
    request<any>(`/incidents/${id}/status`, { method: "POST", body: JSON.stringify({ status }) }),
  users: () => request<any[]>("/users"),
  assets: () => request<any[]>("/assets"),
  availableActions: () => request<any>("/actions/available"),
  actions: (status?: string) => request<any[]>(`/actions${status ? `?status=${status}` : ""}`),
  requestAction: (action_type: string, target: string, incident_id?: number) =>
    request<any>("/actions", { method: "POST", body: JSON.stringify({ action_type, target, incident_id }) }),
  approveAction: (id: number) => request<any>(`/actions/${id}/approve`, { method: "POST" }),
  rejectAction: (id: number) => request<any>(`/actions/${id}/reject`, { method: "POST" }),
  chat: (question: string, history?: any[]) =>
    request<{ answer: string; ai_generated: boolean }>("/chat", {
      method: "POST",
      body: JSON.stringify({ question, history }),
    }),
  detections: () => request<any[]>("/detections"),
  detection: (detId: string) => request<any>(`/detections/${detId}`),
  providers: () => request<any[]>("/providers"),
  connections: () => request<any[]>("/connections"),
  createConnection: (provider: string, display_name: string, credentials: Record<string, string>, enabled = true) =>
    request<any>("/connections", { method: "POST", body: JSON.stringify({ provider, display_name, credentials, enabled }) }),
  updateConnection: (id: number, body: any) =>
    request<any>(`/connections/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  testConnection: (id: number) => request<any>(`/connections/${id}/test`, { method: "POST" }),
  deleteConnection: (id: number) => request<any>(`/connections/${id}`, { method: "DELETE" }),
  reports: () => request<any[]>("/reports"),
  report: (id: number) => request<any>(`/reports/${id}`),
  generateReport: () => request<any>("/reports/generate", { method: "POST" }),
  injectScenario: (scenario?: string) =>
    request<any>("/control/inject", { method: "POST", body: JSON.stringify({ scenario }) }),
  meta: () => request<any>("/connectors"),
  getMode: () => request<{ data_mode: string }>("/mode"),
  setMode: (data_mode: string) =>
    request<{ data_mode: string }>("/mode", { method: "POST", body: JSON.stringify({ data_mode }) }),
};

export function riskColor(score: number): string {
  if (score >= 75) return "#f43f5e";
  if (score >= 50) return "#fb923c";
  if (score >= 25) return "#facc15";
  return "#34d399";
}

export function riskBand(score: number): string {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

export function threatLabel(t: string): string {
  return (t || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
