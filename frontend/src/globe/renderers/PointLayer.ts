import * as Cesium from 'cesium';

import { colorFor, type ColorRule } from '../../layers/colors';
import type { LayerSpec } from '../../layers/types';
import { featureHeight } from '../scaling';
import type { LayerRenderer, RenderFeature } from './types';

const SIZE_BY: Record<string, (v: number) => number> = {
  magnitude: (m) => Math.max(3, m * 2.2),
  frp: (f) => Math.max(3, Math.min(14, 3 + Math.sqrt(f))),
};

/** Distinct CSS colours kept per layer; ramps are quantised, so this only overflows on pathological input. */
const COLOR_CACHE_MAX = 4096;
const scratchPosition = new Cesium.Cartesian3();

/** GPU point primitives: fine for 100k+ features per layer. */
export class PointLayer implements LayerRenderer {
  readonly layerId: string;
  private readonly points = new Cesium.PointPrimitiveCollection();
  private readonly index = new Map<string, Cesium.PointPrimitive>();
  private readonly rule: ColorRule;
  private readonly colors = new Map<string, Cesium.Color>();
  /** For absolute layers coloured by altitude, a feature without `altitude_m` is coloured by its own height. */
  private readonly altitudeFallback: boolean;

  constructor(private readonly scene: Cesium.Scene, private readonly spec: LayerSpec) {
    this.layerId = spec.id;
    this.rule = { base: spec.color, attribute: spec.colorBy.attribute, scale: spec.colorBy.scale };
    this.altitudeFallback = spec.altitude === 'absolute' && spec.colorBy.attribute === 'altitude_m';
    scene.primitives.add(this.points);
  }

  /** Cesium colours are parsed once per CSS string (points copy the colour, so sharing one instance is safe). */
  private color(css: string): Cesium.Color {
    let c = this.colors.get(css);
    if (!c) {
      if (this.colors.size >= COLOR_CACHE_MAX) this.colors.clear();
      c = Cesium.Color.fromCssColorString(css);
      if (this.spec.render === 'heat') c = c.withAlpha(0.45);
      this.colors.set(css, c);
    }
    return c;
  }

  private style(f: RenderFeature) {
    const color = this.color(colorFor(this.rule, f.props, this.altitudeFallback ? f.alt : undefined));
    const sizer = SIZE_BY[this.spec.colorBy.attribute];
    const raw = f.props[this.spec.colorBy.attribute];
    const size = sizer && typeof raw === 'number' ? sizer(raw) : this.spec.render === 'heat' ? 4 : 6;
    return { color, pixelSize: size };
  }

  setFeatures(features: RenderFeature[]): void {
    this.points.removeAll();
    this.index.clear();
    for (const f of features) this.upsert(f);
  }

  upsert(f: RenderFeature): void {
    // positions are copied by the point, so one scratch vector serves every update
    const position = Cesium.Cartesian3.fromDegrees(f.lon, f.lat, featureHeight(this.spec.altitude, f.alt), undefined, scratchPosition);
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
      // Always depth-tested: with depthTestAgainstTerrain off (viewer.ts) only Cesium's horizon depth plane occludes,
      // which hides the far side of the globe; Infinity would force clamped points onto the near plane and draw
      // vessels and quakes on the other hemisphere through the Earth.
      disableDepthTestDistance: 0,
      id: f,
    });
    this.index.set(f.id, p);
  }

  remove(id: string): void {
    const p = this.index.get(id);
    if (!p) return;
    this.points.remove(p);
    this.index.delete(id);
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
