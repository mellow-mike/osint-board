import * as Cesium from 'cesium';
import * as satellite from 'satellite.js';

import { categoricalColor } from '../../layers/colors';
import type { LayerSpec } from '../../layers/types';
import type { LayerRenderer, RenderFeature } from './types';

interface Sat {
  feature: RenderFeature;
  satrec: satellite.SatRec;
  point: Cesium.PointPrimitive;
}

/**
 * Satellites are propagated with SGP4 from their element sets at the scene clock's time, so scrubbing
 * the timeline moves every object along its real orbit at its real altitude (ECI → ECEF via GMST, then
 * geodetic on WGS84 — the same maths as backend/osint_board/geo/satellites.py).
 */
export class OrbitLayer implements LayerRenderer {
  readonly layerId: string;
  private readonly points = new Cesium.PointPrimitiveCollection();
  private readonly sats = new Map<string, Sat>();
  private lastTick = 0;
  private visible = false;
  private readonly tickHandler: () => void;
  private readonly removeTick: Cesium.Event.RemoveCallback;

  constructor(private readonly viewer: Cesium.Viewer, private readonly spec: LayerSpec) {
    this.layerId = spec.id;
    viewer.scene.primitives.add(this.points);
    this.tickHandler = () => this.tick();
    this.removeTick = viewer.clock.onTick.addEventListener(this.tickHandler);
  }

  setFeatures(features: RenderFeature[]): void {
    this.points.removeAll();
    this.sats.clear();
    for (const f of features) this.upsert(f);
    this.lastTick = 0;
    this.tick(true);
  }

  upsert(f: RenderFeature): void {
    const line1 = f.props['line1'];
    const line2 = f.props['line2'];
    if (typeof line1 !== 'string' || typeof line2 !== 'string') return;
    const satrec = satellite.twoline2satrec(line1, line2);
    const color = Cesium.Color.fromCssColorString(categoricalColor(this.spec.color, String(f.props['object_class'] ?? 'active')));
    const existing = this.sats.get(f.id);
    if (existing) {
      existing.satrec = satrec;
      existing.feature = f;
      return;
    }
    const point = this.points.add({
      position: Cesium.Cartesian3.ZERO,
      color,
      pixelSize: 3,
      id: f,
      show: false,
    });
    this.sats.set(f.id, { feature: f, satrec, point });
  }

  private tick(force = false): void {
    if (!this.visible && !force) return;
    const now = performance.now();
    if (!force && now - this.lastTick < 1000) return; // 1 Hz is plenty for a global overview
    this.lastTick = now;
    const date = Cesium.JulianDate.toDate(this.viewer.clock.currentTime);
    const gmst = satellite.gstime(date);
    for (const s of this.sats.values()) {
      const pv = satellite.propagate(s.satrec, date);
      const eci = pv?.position;
      if (!eci || typeof eci === 'boolean') {
        s.point.show = false;
        continue;
      }
      const geo = satellite.eciToGeodetic(eci, gmst);
      s.point.position = Cesium.Cartesian3.fromRadians(geo.longitude, geo.latitude, geo.height * 1000);
      s.point.show = this.visible;
      s.feature.lat = satellite.degreesLat(geo.latitude);
      s.feature.lon = satellite.degreesLong(geo.longitude);
      s.feature.alt = geo.height * 1000;
    }
  }

  setVisible(visible: boolean): void {
    this.visible = visible;
    this.points.show = visible;
    if (visible) this.tick(true);
  }

  count(): number {
    return this.sats.size;
  }

  destroy(): void {
    this.removeTick();
    if (!this.viewer.isDestroyed()) this.viewer.scene.primitives.remove(this.points);
  }
}
