export type LayerGroup = 'live' | 'events' | 'static' | 'investigation';
export type RenderMode = 'points' | 'tracks' | 'orbits' | 'heat' | 'halos';
export type ColorScale = 'categorical' | 'sequential' | 'diverging';

export interface LayerSpec {
  id: string;
  name: string;
  group: LayerGroup;
  color: string;
  colorBy: { attribute: string; scale: ColorScale };
  entityTypes: string[];
  render: RenderMode;
  update: string; // stream | poll:<interval> | static | on_demand
  altitude: 'clamp' | 'absolute';
  defaultVisible: boolean;
  tiled: boolean;
  sources: string[];
  description: string;
  /** Features whose last position/observation is older than this many seconds are stale and dropped; null = keep. */
  maxAgeS: number | null;
  /** Credit line the data sources require while the layer is shown (licence terms), if any. */
  attribution: string | null;
}
