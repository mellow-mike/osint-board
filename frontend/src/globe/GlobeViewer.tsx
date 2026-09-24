import * as Cesium from 'cesium';
import { useEffect, useRef, useState } from 'react';

import { useStore } from '../state/store';
import type { RenderFeature } from './renderers/types';
import { metersPerPixel } from './scaling';
import { useLayerRendering } from './useLayerRendering';
import { createViewer } from './viewer';
import { readViewport } from './viewport';

function pickedFeature(picked: unknown): RenderFeature | null {
  if (!picked || typeof picked !== 'object') return null;
  const obj = picked as { id?: unknown; primitive?: unknown };
  const id = obj.id;
  if (id && typeof id === 'object' && 'layer' in id && 'lon' in id) return id as RenderFeature;
  if (id instanceof Cesium.Entity) {
    const f = id.properties?.getValue(Cesium.JulianDate.now())?.feature as RenderFeature | undefined;
    return f ?? null;
  }
  return null;
}

export function GlobeViewer() {
  const container = useRef<HTMLDivElement>(null);
  const [viewer, setViewer] = useState<Cesium.Viewer | null>(null);
  const select = useStore((s) => s.select);
  const flyTo = useStore((s) => s.flyTo);
  const requestFlyTo = useStore((s) => s.requestFlyTo);
  const setMetersPerPixel = useStore((s) => s.setMetersPerPixel);
  const setClockIso = useStore((s) => s.setClockIso);
  const setViewport = useStore((s) => s.setViewport);

  useEffect(() => {
    let disposed = false;
    let created: Cesium.Viewer | null = null;
    if (!container.current) return;
    createViewer(container.current).then((v) => {
      if (disposed) {
        v.destroy();
        return;
      }
      created = v;
      setViewer(v);
    });
    return () => {
      disposed = true;
      setViewer(null);
      created?.destroy();
    };
  }, []);

  useLayerRendering(viewer);

  useEffect(() => {
    if (!viewer) return;
    const handler = new Cesium.ScreenSpaceEventHandler(viewer.scene.canvas);
    handler.setInputAction((movement: Cesium.ScreenSpaceEventHandler.PositionedEvent) => {
      const f = pickedFeature(viewer.scene.pick(movement.position));
      select(f ? { id: f.id, layer: f.layer, name: f.name, lat: f.lat, lon: f.lon, alt: f.alt, props: f.props } : null);
    }, Cesium.ScreenSpaceEventType.LEFT_CLICK);

    let last = 0;
    const remove = viewer.scene.postRender.addEventListener(() => {
      const now = performance.now();
      if (now - last < 500) return;
      last = now;
      setMetersPerPixel(metersPerPixel(viewer.scene));
      setClockIso(Cesium.JulianDate.toIso8601(viewer.clock.currentTime, 0));
    });
    return () => {
      handler.destroy();
      remove();
    };
  }, [viewer, select, setMetersPerPixel, setClockIso]);

  useEffect(() => {
    if (!viewer) return;
    const update = () => setViewport(readViewport(viewer));
    update();
    const remove = viewer.camera.moveEnd.addEventListener(update);
    return () => {
      remove();
      setViewport(null);
    };
  }, [viewer, setViewport]);

  useEffect(() => {
    if (!viewer || !flyTo) return;
    viewer.camera.flyTo({
      destination: Cesium.Cartesian3.fromDegrees(flyTo.lon, flyTo.lat, flyTo.height ?? Math.max((flyTo.alt ?? 0) * 3, 250_000)),
      duration: 1.6,
    });
    requestFlyTo(null);
  }, [viewer, flyTo, requestFlyTo]);

  return <div ref={container} className="absolute inset-0" />;
}
