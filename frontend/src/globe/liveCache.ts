// Live-layer state kept outside Cesium so it can be unit-tested: the renderers only ever draw what this holds.

import type { LiveDelta } from '../api/types';
import type { TimeWindow } from '../state/store';
import type { RenderFeature } from './renderers/types';

const WINDOW_S: Record<TimeWindow, number> = { '1h': 3600, '24h': 86_400, '7d': 604_800, '30d': 2_592_000 };

/** How long a streamed feature stays: the layer's max age, narrowed by the UI time window (the server clamps alike). */
export function liveMaxAgeS(maxAgeS: number | null, window: TimeWindow): number {
  return Math.min(maxAgeS ?? Number.POSITIVE_INFINITY, WINDOW_S[window]);
}

/** Epoch ms from an ISO string (or a finite number), else undefined. */
export function parseTs(v: unknown): number | undefined {
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v !== 'string' || v === '') return undefined;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : undefined;
}

/** Older than `maxAgeS` at `serverNow`. Features without a time never expire here (the server bounds them). */
export function isExpired(f: Pick<RenderFeature, 'ts'>, maxAgeS: number | null, serverNow: number): boolean {
  return maxAgeS !== null && f.ts !== undefined && f.ts < serverNow - maxAgeS * 1000;
}

/** A snapshot without the features that are already stale (cached query data can be minutes old when re-shown). */
export function dropExpired(features: RenderFeature[], maxAgeS: number | null, serverNow: number): RenderFeature[] {
  return maxAgeS === null ? features : features.filter((f) => !isExpired(f, maxAgeS, serverNow));
}

/**
 * `prev` updated by one delta, or null when the delta is older than what is already shown (two sources report the
 * same aircraft with different latencies; the older fix must not move it backwards). Deltas are partial: their props
 * are merged over the previous ones, so colour attributes, precision and entity type survive position-only updates.
 */
export function mergeDelta(layer: string, prev: RenderFeature | undefined, d: LiveDelta): RenderFeature | null {
  const ts = parseTs(d.ts);
  if (prev?.ts !== undefined && ts !== undefined && ts < prev.ts) return null;
  const props: Record<string, unknown> = { ...prev?.props, ...d.props };
  if (d.hdg !== undefined) props['heading'] = d.hdg;
  if (d.spd !== undefined) props['speed'] = d.spd;
  props['time'] = d.ts;
  return {
    id: d.id,
    layer,
    lon: d.lon,
    lat: d.lat,
    alt: d.alt ?? null,
    name: d.name ?? prev?.name ?? d.id,
    props,
    ts: ts ?? prev?.ts,
  };
}

interface Entry {
  f: RenderFeature;
  /** local Date.now() when the client learned this state (snapshot request start, or delta arrival) */
  receivedAt: number;
}

/**
 * Current state of one streamed layer: the last snapshot from /api/layers/{id}/features merged with the deltas that
 * arrived since. Changed ids are remembered until the renderer takes them (`takeDirty`), so a burst of deltas costs
 * one redraw per feature per flush.
 */
export class LiveCache {
  /** Features whose `ts` is older than this are swept (the layer's max age, narrowed by the UI time window). */
  maxAgeS: number | null;
  private entries = new Map<string, Entry>();
  private readonly dirty = new Set<string>();

  constructor(
    readonly layerId: string,
    maxAgeS: number | null = null,
  ) {
    this.maxAgeS = maxAgeS;
  }

  get size(): number {
    return this.entries.size;
  }

  get(id: string): RenderFeature | undefined {
    return this.entries.get(id)?.f;
  }

  values(): RenderFeature[] {
    return Array.from(this.entries.values(), (e) => e.f);
  }

  isDirty(id: string): boolean {
    return this.dirty.has(id);
  }

  /** Merge deltas received at local time `receivedAt`; returns how many changed the cache (stale and old ones don't). */
  applyDeltas(deltas: readonly LiveDelta[], at: { receivedAt: number; serverNow: number }): number {
    let applied = 0;
    for (const d of deltas) {
      const prev = this.entries.get(d.id);
      const f = mergeDelta(this.layerId, prev?.f, d);
      if (!f || isExpired(f, this.maxAgeS, at.serverNow)) continue;
      this.entries.set(d.id, { f, receivedAt: at.receivedAt });
      this.dirty.add(d.id);
      applied++;
    }
    return applied;
  }

  /**
   * Replace the cache with a snapshot requested at local time `requestedAt`. The snapshot is the truth as of its
   * request: an id it lacks survives only if a delta delivered it after the request started, and per id the newer
   * `ts` wins (a live entry newer than the snapshot keeps its position, gaining props the deltas don't carry).
   * Stale snapshot rows are dropped. Returns the ids that disappeared; the caller redraws the whole layer.
   */
  applySnapshot(features: readonly RenderFeature[], at: { requestedAt: number; serverNow: number }): string[] {
    const next = new Map<string, Entry>();
    for (const s of features) {
      if (isExpired(s, this.maxAgeS, at.serverNow)) continue;
      const cur = this.entries.get(s.id);
      if (cur && cur.f.ts !== undefined && (s.ts === undefined || cur.f.ts > s.ts)) {
        next.set(s.id, { f: { ...cur.f, props: { ...s.props, ...cur.f.props } }, receivedAt: cur.receivedAt });
      } else {
        next.set(s.id, { f: s, receivedAt: at.requestedAt });
      }
    }
    const removed: string[] = [];
    for (const [id, cur] of this.entries) {
      if (next.has(id)) continue;
      if (cur.receivedAt >= at.requestedAt && !isExpired(cur.f, this.maxAgeS, at.serverNow)) next.set(id, cur);
      else removed.push(id);
    }
    this.entries = next;
    this.dirty.clear();
    return removed;
  }

  /** Changed features since the last call; clears the change set. */
  takeDirty(): RenderFeature[] {
    const out: RenderFeature[] = [];
    for (const id of this.dirty) {
      const e = this.entries.get(id);
      if (e) out.push(e.f);
    }
    this.dirty.clear();
    return out;
  }

  /** Drop features older than `maxAgeS` at `serverNow`; returns their ids. */
  sweep(serverNow: number): string[] {
    if (this.maxAgeS === null) return [];
    const gone: string[] = [];
    for (const [id, e] of this.entries) {
      if (!isExpired(e.f, this.maxAgeS, serverNow)) continue;
      this.entries.delete(id);
      this.dirty.delete(id);
      gone.push(id);
    }
    return gone;
  }

  clear(): void {
    this.entries.clear();
    this.dirty.clear();
  }
}

/**
 * The server's clock as seen from here. Feature times come from the server and its sources, so ages are measured
 * against `Date.now()` corrected by the offset observed from `FeatureCollection.generated_at` (never the Cesium
 * clock, which the user scrubs).
 */
export class ServerClock {
  private skew = 0;

  /** `generatedAt`: the server's time when it built a response that arrived here at local time `localMs`. */
  observe(generatedAt: string | null | undefined, localMs: number): void {
    const t = parseTs(generatedAt);
    if (t !== undefined) this.skew = t - localMs;
  }

  /** server minus local clock, ms */
  get skewMs(): number {
    return this.skew;
  }

  now(localMs: number = Date.now()): number {
    return localMs + this.skew;
  }
}
