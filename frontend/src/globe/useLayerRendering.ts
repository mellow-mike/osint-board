import { useQueries } from '@tanstack/react-query';
import type * as Cesium from 'cesium';
import { useEffect, useMemo, useRef } from 'react';

import { api, openStream } from '../api/client';
import type { FeatureCollection, GeoFeature, LiveDelta } from '../api/types';
import { LAYERS, pollIntervalMs } from '../layers/registry';
import type { LayerSpec } from '../layers/types';
import { useStore } from '../state/store';
import { HaloLayer } from './renderers/HaloLayer';
import { OrbitLayer } from './renderers/OrbitLayer';
import { PointLayer } from './renderers/PointLayer';
import { PrecisionSplitLayer } from './renderers/PrecisionSplitLayer';
import type { LayerRenderer, RenderFeature } from './renderers/types';
import { tiledInRange, type Viewport } from './viewport';

function toRenderFeature(layer: string, f: GeoFeature): RenderFeature | null {
  if (!f.geometry) {
    return { id: f.id, layer, lon: 0, lat: 0, alt: null, name: String(f.properties.name ?? f.id), props: f.properties };
  }
  const [lon, lat, alt] = f.geometry.coordinates;
  return { id: f.id, layer, lon, lat, alt: alt ?? null, name: String(f.properties.name ?? f.id), props: f.properties };
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

/** Tiled layers hold millions of rows: fetch only what the camera sees, and nothing when zoomed out. */
async function viewportFeatures(layerId: string, viewport: Viewport | null): Promise<FeatureCollection> {
  if (!tiledInRange(viewport)) return { type: 'FeatureCollection', features: [], layer: layerId, count: 0, generated_at: null };
  const parts = await Promise.all(viewport.bboxes.map((bbox) => api.features(layerId, { bbox, limit: 20000 })));
  const features = parts.flatMap((p) => p.features);
  return { ...parts[0]!, features, count: features.length };
}

/** Creates one renderer per catalog layer, feeds it from /api/layers/{id}/features and from the live stream. */
export function useLayerRendering(viewer: Cesium.Viewer | null): void {
  const visible = useStore((s) => s.visible);
  const timeWindow = useStore((s) => s.timeWindow);
  const setCount = useStore((s) => s.setCount);
  const viewport = useStore((s) => s.viewport);
  const renderers = useRef(new Map<string, LayerRenderer>());

  useEffect(() => {
    if (!viewer) return;
    const map = renderers.current;
    for (const spec of LAYERS) map.set(spec.id, makeRenderer(viewer, spec));
    return () => {
      for (const r of map.values()) r.destroy();
      map.clear();
    };
  }, [viewer]);

  const activeLayers = useMemo(() => LAYERS.filter((l) => visible[l.id]), [visible]);

  const queries = useQueries({
    queries: activeLayers.map((l) =>
      l.tiled
        ? {
            queryKey: ['features', l.id, tiledInRange(viewport) ? viewport.bboxes.join('|') : 'zoomed-out'],
            queryFn: () => viewportFeatures(l.id, viewport),
            refetchInterval: false as const,
            staleTime: 300_000,
            enabled: !!viewer,
          }
        : {
            queryKey: ['features', l.id, l.group === 'events' || l.group === 'live' ? timeWindow : 'all'],
            queryFn: () => api.features(l.id, { since: l.group === 'static' ? undefined : timeWindow, limit: 20000 }),
            refetchInterval: pollIntervalMs(l.update) ?? false,
            staleTime: 30_000,
            enabled: !!viewer,
          },
    ),
  });

  useEffect(() => {
    queries.forEach((q, i) => {
      const spec = activeLayers[i];
      const data = q.data as FeatureCollection | undefined;
      const r = spec && renderers.current.get(spec.id);
      if (!spec || !r || !data) return;
      const feats = data.features.map((f) => toRenderFeature(spec.id, f)).filter((f): f is RenderFeature => f !== null);
      r.setFeatures(feats);
      setCount(spec.id, r.count());
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queries.map((q) => q.dataUpdatedAt).join(','), activeLayers, setCount]);

  useEffect(() => {
    for (const [id, r] of renderers.current) r.setVisible(!!visible[id]);
  }, [visible, viewer]);

  const liveIds = useMemo(() => activeLayers.filter((l) => l.update === 'stream').map((l) => l.id), [activeLayers]);
  useEffect(() => {
    if (!viewer || liveIds.length === 0) return;
    const dispose = openStream(liveIds, (layer: string, d: LiveDelta) => {
      const r = renderers.current.get(layer);
      if (!r) return;
      r.upsert({ id: d.id, layer, lon: d.lon, lat: d.lat, alt: d.alt, name: d.name ?? d.id, props: { ...(d.props ?? {}), heading: d.hdg, speed: d.spd, time: d.ts } });
      setCount(layer, r.count());
    });
    return dispose;
  }, [viewer, liveIds, setCount]);
}
