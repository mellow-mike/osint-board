export interface RenderFeature {
  id: string;
  layer: string;
  lon: number;
  lat: number;
  alt: number | null;
  name: string;
  props: Record<string, unknown>;
}

export interface LayerRenderer {
  readonly layerId: string;
  setFeatures(features: RenderFeature[]): void;
  /** Merge one feature (live delta). */
  upsert(feature: RenderFeature): void;
  remove(id: string): void;
  setVisible(visible: boolean): void;
  count(): number;
  destroy(): void;
}
