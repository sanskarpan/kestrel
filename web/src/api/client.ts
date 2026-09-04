// web/src/api/client.ts — typed fetch wrapper for kestreld REST API
// Base: http://localhost:7777/v1 (proxied via vite as /v1) + /run/kestrel.sock

const BASE = "";

type FetchOpts = RequestInit & { params?: Record<string, string> };

async function request<T>(path: string, opts: FetchOpts = {}): Promise<T> {
  const url = new URL(`${BASE}${path}`, window.location.origin);
  if (opts.params) {
    for (const [k, v] of Object.entries(opts.params)) url.searchParams.set(k, v);
  }
  const res = await fetch(url.toString(), {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${opts.method || "GET"} ${path} → ${res.status} ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  listContainers: () => request<unknown[]>("/containers"),
  getContainer: (id: string) => request<unknown>(`/containers/${id}`),
  getNamespaces: (id: string) => request<unknown>(`/containers/${id}/namespaces`),
  getCgroup: (id: string) => request<unknown>(`/containers/${id}/cgroup`),
  getPressure: (id: string) => request<unknown>(`/containers/${id}/pressure`),
  getLayers: (id: string) => request<unknown>(`/containers/${id}/layers`),
  getCopyups: (id: string) => request<unknown>(`/containers/${id}/copyups`),
  getMounts: (id: string) => request<unknown>(`/containers/${id}/mounts`),
  getCaps: (id: string) => request<unknown>(`/containers/${id}/caps`),
  getSeccomp: (id: string) => request<unknown>(`/containers/${id}/seccomp`),
  getNetwork: (id: string) => request<unknown>(`/containers/${id}/network`),
  getSystemNamespaces: () => request<unknown>("/system/namespaces"),
  getSystemTopology: () => request<unknown>("/system/topology"),
  listImages: () => request<unknown[]>("/images"),
  eventsUrl: () => "/events",
};
