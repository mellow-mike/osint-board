import type { Coverage, FeatureCollection, Health, LiveDelta, ModuleSpec, SearchResponse, StreamState } from './types';

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

/** What one WebSocket frame means for the client, after validation. */
export type StreamFrame =
  | { kind: 'deltas'; layer: string; deltas: LiveDelta[]; invalid: number }
  | { kind: 'error'; message: string }
  | { kind: 'ignored'; reason: 'malformed' | 'no_layer' | 'not_subscribed' | 'unknown' };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function finite(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/** An optional number: absent stays absent (the client keeps what it has), anything unusable becomes null. */
function optionalNumber(v: unknown): number | null | undefined {
  return v === undefined ? undefined : finite(v);
}

/** A delta the renderers can draw: a known kind, an id, a real position and a parseable time; otherwise null. */
function toDelta(v: unknown): LiveDelta | null {
  if (!isRecord(v) || (v.t !== 'track' && v.t !== 'event')) return null;
  const lon = finite(v.lon);
  const lat = finite(v.lat);
  if (typeof v.id !== 'string' || v.id === '' || lon === null || lat === null) return null;
  if (Math.abs(lon) > 180 || Math.abs(lat) > 90) return null;
  if (typeof v.ts !== 'string' || !Number.isFinite(Date.parse(v.ts))) return null;
  const d: LiveDelta = { t: v.t, id: v.id, lon, lat, alt: finite(v.alt), ts: v.ts };
  const hdg = optionalNumber(v.hdg);
  const spd = optionalNumber(v.spd);
  if (hdg !== undefined) d.hdg = hdg;
  if (spd !== undefined) d.spd = spd;
  if (typeof v.name === 'string' && v.name !== '') d.name = v.name;
  if (isRecord(v.props)) d.props = v.props;
  return d;
}

/**
 * Validates one /api/stream frame and routes it strictly by its `layer`: a frame without one is dropped rather than
 * guessed (two live layers are usually subscribed at once), as is one for a layer this socket did not ask for.
 * Batches and legacy single deltas both come out as a list; invalid items are counted and skipped.
 */
export function parseFrame(raw: unknown, subscribed?: ReadonlySet<string>): StreamFrame {
  if (typeof raw !== 'string') return { kind: 'ignored', reason: 'malformed' };
  let msg: unknown;
  try {
    msg = JSON.parse(raw);
  } catch {
    return { kind: 'ignored', reason: 'malformed' };
  }
  if (!isRecord(msg)) return { kind: 'ignored', reason: 'malformed' };
  if (msg.type === 'error') {
    return { kind: 'error', message: typeof msg.message === 'string' && msg.message ? msg.message : 'live stream error' };
  }
  const layer = msg.layer;
  if (typeof layer !== 'string' || layer === '') return { kind: 'ignored', reason: 'no_layer' };
  if (subscribed && !subscribed.has(layer)) return { kind: 'ignored', reason: 'not_subscribed' };
  let items: unknown[];
  if (msg.t === 'batch') items = Array.isArray(msg.items) ? msg.items : [];
  else if (msg.t === 'track' || msg.t === 'event') items = [msg];
  else return { kind: 'ignored', reason: 'unknown' };
  const deltas: LiveDelta[] = [];
  for (const item of items) {
    const d = toDelta(item);
    if (d) deltas.push(d);
  }
  return { kind: 'deltas', layer, deltas, invalid: items.length - deltas.length };
}

export interface StreamHandlers {
  /** Validated deltas of one frame for one subscribed layer. Exceptions are logged, never swallowed silently. */
  onDeltas: (layer: string, deltas: LiveDelta[]) => void;
  /** The stream is live again after a gap (drop or server error): deltas were missed, so snapshots should be refetched. */
  onReconnect?: () => void;
  onState?: (state: StreamState) => void;
}

/** A socket that stayed up this long without an error frame counts as live (the server errors right after accept). */
const HEALTHY_AFTER_MS = 3000;

/**
 * Subscribe to live deltas; returns a disposer. Reconnects with backoff, which only resets once a connection has
 * proven live (data, or a few seconds without an error frame) so a server that errors on accept is not hammered.
 */
export function openStream(layers: string[], handlers: StreamHandlers): () => void {
  const subscribed = new Set(layers);
  let ws: WebSocket | null = null;
  let closed = false;
  let down = false; // the server reported an error; stays down until a later connection proves live
  let gap = false; // a connection dropped or failed since the stream was last live
  let backoff = 1000;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let healthy: ReturnType<typeof setTimeout> | undefined;
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const host = BASE ? new URL(BASE).host : window.location.host;

  const connect = () => {
    if (closed) return;
    let live = false;
    let failed = false;
    const markLive = () => {
      if (live || failed || closed) return;
      live = true;
      down = false;
      backoff = 1000;
      handlers.onState?.({ state: 'live' });
      if (gap) {
        gap = false;
        handlers.onReconnect?.();
      }
    };
    const socket = new WebSocket(`${proto}://${host}/api/stream?layers=${encodeURIComponent(layers.join(','))}`);
    ws = socket;
    socket.onmessage = (ev) => {
      const frame = parseFrame(ev.data, subscribed);
      if (frame.kind === 'error') {
        failed = true;
        down = true;
        handlers.onState?.({ state: 'down', message: frame.message });
        return;
      }
      if (frame.kind !== 'deltas') return;
      markLive();
      if (frame.deltas.length === 0) return;
      try {
        handlers.onDeltas(frame.layer, frame.deltas);
      } catch (err) {
        console.error(`live update for layer ${frame.layer} failed`, err);
      }
    };
    socket.onopen = () => {
      healthy = setTimeout(markLive, HEALTHY_AFTER_MS);
    };
    socket.onclose = () => {
      clearTimeout(healthy);
      if (closed || ws !== socket) return;
      gap = true;
      if (!down) handlers.onState?.({ state: 'connecting' });
      retry = setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 30_000);
    };
  };
  handlers.onState?.({ state: 'connecting' }); // later attempts report it when a socket closes
  connect();
  return () => {
    closed = true;
    clearTimeout(retry);
    clearTimeout(healthy);
    ws?.close();
  };
}
