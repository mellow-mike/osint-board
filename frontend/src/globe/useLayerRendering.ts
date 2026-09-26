import { useQueries, useQueryClient } from '@tanstack/react-query';
import type * as Cesium from 'cesium';
import { useEffect, useMemo, useRef } from 'react';

import { api, openStream } from '../api/client';
import type { FeatureCollection, GeoFeature, LiveDelta } from '../api/types';
import { LAYERS, pollIntervalMs } from '../layers/registry';
import type { LayerSpec } from '../layers/types';
import { useStore } from '../state/store';
import { dropExpired, LiveCache, liveMaxAgeS, parseTs, ServerClock } from './liveCache';
import { HaloLayer } from './renderers/HaloLayer';
import { OrbitLayer } from './renderers/OrbitLayer';
import { PointLayer } from './renderers/PointLayer';
import { PrecisionSplitLayer } from './renderers/PrecisionSplitLayer';
import type { LayerRenderer, RenderFeature } from './renderers/types';
import { tiledInRange, type Viewport } from './viewport';

/** A features response plus the local time its request started (what the live cache needs to merge it). */
type Snapshot = FeatureCollection & { requestedAt: number };

/** Live-layer expiry runs this often. */
const SWEEP_MS = 5000;
/** A delta flush waits for the next frame, or this long when no frame comes (background tab). */
const FLUSH_FALLBACK_MS = 250;

function toRenderFeature(layer: string, f: GeoFeature): RenderFeature {
  const name = String(f.properties.name ?? f.id);
  const ts = parseTs(f.properties.time);
  if (!f.geometry) return { id: f.id, layer, lon: 0, lat: 0, alt: null, name, props: f.properties, ts };
  const [lon, lat, alt] = f.geometry.coordinates;
  return { id: f.id, layer, lon, lat, alt: alt ?? null, name, props: f.properties, ts };
}

function makeRenderer(viewer: Cesium.Viewer, spec: LayerSpec): LayerRenderer {
  switch (spec.render) {
    case 'orbits':
      return new OrbitLayer(viewer, spec);
    case 'halos':
      return new HaloLayer(viewer, spec);
    default: // pins for exact/rooftop/street only; anything coarser becomes a halo
      return new PrecisionSplitLayer(new PointLayer(viewer.scene, spec), new HaloLayer(viewer, spec));
  }
}

async function snapshot(fetch: () => Promise<FeatureCollection>): Promise<Snapshot> {
  const requestedAt = Date.now();
  return { ...(await fetch()), requestedAt };
}

/** Tiled layers hold millions of rows: fetch only what the camera sees, and nothing when zoomed out. */
async function viewportFeatures(layerId: string, viewport: Viewport | null): Promise<FeatureCollection> {
  if (!tiledInRange(viewport)) return { type: 'FeatureCollection', features: [], layer: layerId, count: 0, generated_at: null };
  const parts = await Promise.all(viewport.bboxes.map((bbox) => api.features(layerId, { bbox, limit: 20000 })));
  const features = parts.flatMap((p) => p.features);
  return { ...parts[0]!, features, count: features.length };
}

/** Push the selected feature's new state into the store (the inspector follows a moving aircraft). */
function syncSelected(layer: string, find: (id: string) => RenderFeature | undefined): void {
  const { selected, updateSelected } = useStore.getState();
  if (!selected || selected.layer !== layer) return;
  const f = find(selected.id);
  if (f) updateSelected(layer, f.id, { name: f.name, lat: f.lat, lon: f.lon, alt: f.alt, props: f.props, ts: f.ts, stale: false });
}

/** Mark the selection stale when its feature left the layer (expired, or absent from a fresh snapshot). */
function markGone(layer: string, ids: readonly string[]): void {
  const { selected, updateSelected } = useStore.getState();
  if (selected && selected.layer === layer && !selected.stale && ids.includes(selected.id)) updateSelected(layer, selected.id, { stale: true });
}

/**
 * Creates one renderer per catalog layer, feeds it from /api/layers/{id}/features and, for streamed layers, from the
 * live stream. A streamed layer's state lives in a {@link LiveCache}: snapshots and deltas are merged there (newest
 * fix wins, props merged), features older than the layer's max age are swept, and the renderer is updated in batches.
 */
export function useLayerRendering(viewer: Cesium.Viewer | null): void {
  const visible = useStore((s) => s.visible);
  const timeWindow = useStore((s) => s.timeWindow);
  const setCount = useStore((s) => s.setCount);
  const viewport = useStore((s) => s.viewport);
  const queryClient = useQueryClient();
  const renderers = useRef(new Map<string, LayerRenderer>());
  const caches = useRef(new Map<string, LiveCache>()); // streamed layers only
  const applied = useRef(new Map<string, number>()); // layer id -> dataUpdatedAt of the snapshot last drawn
  const clock = useRef(new ServerClock());
  const flushRef = useRef<{ schedule: () => void; cancel: () => void } | null>(null);

  useEffect(() => {
    if (!viewer) return;
    const map = renderers.current;
    const cacheMap = caches.current;
    const drawn = applied.current;
    for (const spec of LAYERS) {
      map.set(spec.id, makeRenderer(viewer, spec));
      if (spec.update === 'stream') cacheMap.set(spec.id, new LiveCache(spec.id, spec.maxAgeS));
    }

    // Deltas land in the caches as they arrive; renderers catch up once per frame (or 250 ms without frames).
    const flush = () => {
      const { selected } = useStore.getState();
      for (const [id, cache] of cacheMap) {
        const r = map.get(id);
        if (!r) continue;
        const selectedChanged = selected?.layer === id && cache.isDirty(selected.id);
        const changed = cache.takeDirty();
        if (changed.length === 0) continue;
        for (const f of changed) r.upsert(f);
        useStore.getState().setCount(id, r.count());
        if (selectedChanged) syncSelected(id, (fid) => cache.get(fid));
      }
    };
    let raf = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let pending = false;
    const run = () => {
      if (!pending) return;
      pending = false;
      cancelAnimationFrame(raf);
      clearTimeout(timer);
      flush();
    };
    flushRef.current = {
      schedule: () => {
        if (pending) return;
        pending = true;
        raf = requestAnimationFrame(run);
        timer = setTimeout(run, FLUSH_FALLBACK_MS);
      },
      cancel: () => {
        pending = false;
        cancelAnimationFrame(raf);
        clearTimeout(timer);
      },
    };

    // Stream layers get no removal deltas: whatever has not reported within the max age is dropped here.
    const sweep = setInterval(() => {
      const now = clock.current.now();
      for (const [id, cache] of cacheMap) {
        const gone = cache.sweep(now);
        const r = map.get(id);
        if (gone.length === 0 || !r) continue;
        for (const fid of gone) r.remove(fid);
        useStore.getState().setCount(id, r.count());
        markGone(id, gone);
      }
    }, SWEEP_MS);

    return () => {
      clearInterval(sweep);
      flushRef.current?.cancel();
      flushRef.current = null;
      for (const r of map.values()) r.destroy();
      map.clear();
      cacheMap.clear();
      drawn.clear();
    };
  }, [viewer]);

  // The time window narrows how long a streamed feature stays (and the server's snapshot follows the same window).
  useEffect(() => {
    for (const cache of caches.current.values()) {
      const spec = LAYERS.find((l) => l.id === cache.layerId);
      if (spec) cache.maxAgeS = liveMaxAgeS(spec.maxAgeS, timeWindow);
    }
  }, [viewer, timeWindow]);

  const activeLayers = useMemo(() => LAYERS.filter((l) => visible[l.id]), [visible]);

  const queries = useQueries({
    queries: activeLayers.map((l) =>
      l.tiled
        ? {
            queryKey: ['features', l.id, tiledInRange(viewport) ? viewport.bboxes.join('|') : 'zoomed-out'],
            queryFn: () => snapshot(() => viewportFeatures(l.id, viewport)),
            refetchInterval: false as const,
            staleTime: 300_000,
            enabled: !!viewer,
          }
        : {
            queryKey: ['features', l.id, l.group === 'events' || l.group === 'live' ? timeWindow : 'all'],
            queryFn: () => snapshot(() => api.features(l.id, { since: l.group === 'static' ? undefined : timeWindow, limit: 20000 })),
            refetchInterval: pollIntervalMs(l.update) ?? false,
            staleTime: 30_000,
            enabled: !!viewer,
          },
    ),
  });

  // A layer is redrawn only when its own data changed (dataUpdatedAt), never because another layer refetched: a
  // one-minute seismic poll must not reset the aircraft to their positions at page load.
  const tokens = queries.map((q, i) => `${activeLayers[i]?.id}@${q.dataUpdatedAt}`).join(',');
  useEffect(() => {
    queries.forEach((q, i) => {
      const spec = activeLayers[i];
      const data = q.data as Snapshot | undefined;
      const r = spec && renderers.current.get(spec.id);
      if (!spec || !r || !data || applied.current.get(spec.id) === q.dataUpdatedAt) return;
      applied.current.set(spec.id, q.dataUpdatedAt);

      clock.current.observe(data.generated_at, q.dataUpdatedAt);
      useStore.getState().setClockSkew(clock.current.skewMs);
      const now = clock.current.now();
      const feats = data.features.map((f) => toRenderFeature(spec.id, f));
      const cache = caches.current.get(spec.id);
      if (cache) {
        const gone = cache.applySnapshot(feats, { requestedAt: data.requestedAt, serverNow: now });
        r.setFeatures(cache.values());
        markGone(spec.id, gone);
        syncSelected(spec.id, (id) => cache.get(id));
      } else {
        const fresh = dropExpired(feats, spec.maxAgeS, now);
        r.setFeatures(fresh);
        syncSelected(spec.id, (id) => fresh.find((f) => f.id === id));
      }
      setCount(spec.id, r.count());
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tokens, setCount, viewer]);

  useEffect(() => {
    for (const [id, r] of renderers.current) r.setVisible(!!visible[id]);
  }, [visible, viewer]);

  // Keyed by the joined ids, so toggling an unrelated layer does not tear the socket down and lose deltas.
  const liveKey = activeLayers
    .filter((l) => l.update === 'stream')
    .map((l) => l.id)
    .join(',');
  const liveIds = useMemo(() => (liveKey ? liveKey.split(',') : []), [liveKey]);
  useEffect(() => {
    if (!viewer || liveIds.length === 0) return;
    const { setStream } = useStore.getState();
    const dispose = openStream(liveIds, {
      onDeltas: (layer: string, deltas: LiveDelta[]) => {
        const cache = caches.current.get(layer);
        if (!cache) return;
        if (cache.applyDeltas(deltas, { receivedAt: Date.now(), serverNow: clock.current.now() }) > 0) flushRef.current?.schedule();
      },
      // deltas were missed while the socket was down: refetch the snapshots they would have updated
      onReconnect: () => {
        for (const id of liveIds) void queryClient.invalidateQueries({ queryKey: ['features', id] });
      },
      onState: setStream,
    });
    return () => {
      dispose();
      setStream(null);
    };
  }, [viewer, liveIds, queryClient]);
}
