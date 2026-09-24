import * as Cesium from 'cesium';

import { colorFor, type ColorRule } from '../../layers/colors';
import type { LayerSpec } from '../../layers/types';
import type { LayerRenderer, RenderFeature } from './types';

/** Uncertainty radius (m) per precision — keep in sync with backend/osint_board/geo/precision.py. */
export const PRECISION_RADIUS_M: Record<string, number> = {
  exact: 0,
  rooftop: 15,
  street: 150,
  city: 15_000,
  region: 150_000,
  country: 600_000,
};

/**
 * Low-precision placements (IP geolocation, country centroids, profile locations) are drawn as translucent
 * discs sized by their uncertainty, never as pins, so the globe never over-claims what we know.
 */
export class HaloLayer implements LayerRenderer {
  readonly layerId: string;
  private readonly source = new Cesium.CustomDataSource();
  private readonly rule: ColorRule;

  constructor(private readonly viewer: Cesium.Viewer, spec: LayerSpec) {
    this.layerId = spec.id;
    this.rule = { base: spec.color, attribute: spec.colorBy.attribute, scale: spec.colorBy.scale };
    void viewer.dataSources.add(this.source);
  }

  private radius(f: RenderFeature): number {
    const p = String(f.props['precision'] ?? f.props['geo_precision'] ?? 'city');
    return Math.max(PRECISION_RADIUS_M[p] ?? 15_000, 2_000);
  }

  setFeatures(features: RenderFeature[]): void {
    this.source.entities.suspendEvents();
    this.source.entities.removeAll();
    for (const f of features) this.upsert(f);
    this.source.entities.resumeEvents();
  }

  upsert(f: RenderFeature): void {
    const color = Cesium.Color.fromCssColorString(colorFor(this.rule, f.props));
    const r = this.radius(f);
    const existing = this.source.entities.getById(f.id);
    if (existing) this.source.entities.remove(existing);
    const entity = this.source.entities.add({
      id: f.id,
      name: f.name,
      position: Cesium.Cartesian3.fromDegrees(f.lon, f.lat, 0),
      ellipse: {
        semiMajorAxis: r,
        semiMinorAxis: r,
        material: color.withAlpha(0.18),
        outline: true,
        outlineColor: color.withAlpha(0.8),
        outlineWidth: 1,
        height: 0,
      },
      point: r <= 2_000 ? { pixelSize: 6, color, outlineColor: Cesium.Color.BLACK, outlineWidth: 1 } : undefined,
    });
    entity.properties = new Cesium.PropertyBag({ feature: f });
  }

  setVisible(visible: boolean): void {
    this.source.show = visible;
  }

  count(): number {
    return this.source.entities.values.length;
  }

  destroy(): void {
    if (!this.viewer.isDestroyed()) this.viewer.dataSources.remove(this.source, true);
  }
}
