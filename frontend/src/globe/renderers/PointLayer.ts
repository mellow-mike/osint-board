import * as Cesium from 'cesium';

import { colorFor, type ColorRule } from '../../layers/colors';
import type { LayerSpec } from '../../layers/types';
import { featureHeight } from '../scaling';
import type { LayerRenderer, RenderFeature } from './types';

const SIZE_BY: Record<string, (v: number) => number> = {
  magnitude: (m) => Math.max(3, m * 2.2),
  frp: (f) => Math.max(3, Math.min(14, 3 + Math.sqrt(f))),
};

/** GPU point primitives: fine for 100k+ features per layer. */
export class PointLayer implements LayerRenderer {
  readonly layerId: string;
  private readonly points = new Cesium.PointPrimitiveCollection();
  private readonly index = new Map<string, Cesium.PointPrimitive>();
  private readonly rule: ColorRule;

  constructor(private readonly scene: Cesium.Scene, private readonly spec: LayerSpec) {
    this.layerId = spec.id;
    this.rule = { base: spec.color, attribute: spec.colorBy.attribute, scale: spec.colorBy.scale };
    scene.primitives.add(this.points);
  }

  private style(f: RenderFeature) {
    const color = Cesium.Color.fromCssColorString(colorFor(this.rule, f.props));
    const sizer = SIZE_BY[this.spec.colorBy.attribute];
    const raw = f.props[this.spec.colorBy.attribute];
    const size = sizer && typeof raw === 'number' ? sizer(raw) : this.spec.render === 'heat' ? 4 : 6;
    return { color: this.spec.render === 'heat' ? color.withAlpha(0.45) : color, pixelSize: size };
  }

  setFeatures(features: RenderFeature[]): void {
    this.points.removeAll();
    this.index.clear();
    for (const f of features) this.upsert(f);
  }

  upsert(f: RenderFeature): void {
    const position = Cesium.Cartesian3.fromDegrees(f.lon, f.lat, featureHeight(this.spec.altitude, f.alt));
    const { color, pixelSize } = this.style(f);
    const existing = this.index.get(f.id);
    if (existing) {
      existing.position = position;
      existing.color = color;
      existing.pixelSize = pixelSize;
      existing.id = f;
      return;
    }
    const p = this.points.add({
      position,
      color,
      pixelSize,
      outlineColor: Cesium.Color.BLACK.withAlpha(0.6),
      outlineWidth: 1,
      disableDepthTestDistance: this.spec.altitude === 'clamp' ? Number.POSITIVE_INFINITY : 0,
      id: f,
    });
    this.index.set(f.id, p);
  }

  setVisible(visible: boolean): void {
    this.points.show = visible;
  }

  count(): number {
    return this.index.size;
  }

  destroy(): void {
    if (!this.scene.isDestroyed()) this.scene.primitives.remove(this.points);
  }
}
