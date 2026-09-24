import type { Coverage, FeatureCollection, Health, LiveDelta, ModuleSpec, SearchResponse } from './types';

const BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '');

async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(`${BASE}/api${path}`, window.location.origin);
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== '') url.searchParams.set(k, String(v));
  }
  const res = await fetch(url.toString(), { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${path}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => get<Health>('/health'),
  modules: (params?: { consumes?: string; status?: string; phase?: number; mode?: string }) => get<ModuleSpec[]>('/catalog/modules', params),
  coverage: () => get<Coverage>('/catalog/coverage'),
  search: (q: string, investigationId?: string) => get<SearchResponse>('/search', { q, investigation_id: investigationId, limit: 25 }),
  features: (layerId: string, opts: { since?: string; bbox?: string; limit?: number } = {}) =>
    get<FeatureCollection>(`/layers/${layerId}/features`, opts),
  runModule: async (moduleId: string, body: { entity_type: string; value: string; investigation_id?: string }) => {
    const res = await fetch(`${BASE}/api/modules/${moduleId}/run`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    return (await res.json()) as { run_id: string; status: string };
  },
};

/** Subscribe to live deltas; returns a disposer. Reconnects with backoff. */
export function openStream(layers: string[], onDelta: (layer: string, d: LiveDelta) => void): () => void {
  let ws: WebSocket | null = null;
  let closed = false;
  let backoff = 1000;
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const host = BASE ? new URL(BASE).host : window.location.host;

  const connect = () => {
    if (closed) return;
    ws = new WebSocket(`${proto}://${host}/api/stream?layers=${encodeURIComponent(layers.join(','))}`);
    ws.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data as string) as LiveDelta & { layer?: string };
        onDelta(d.layer ?? layers[0] ?? '', d);
      } catch {
        /* ignore malformed frames */
      }
    };
    ws.onopen = () => {
      backoff = 1000;
    };
    ws.onclose = () => {
      if (!closed) {
        setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 30_000);
      }
    };
  };
  connect();
  return () => {
    closed = true;
    ws?.close();
  };
}
