import { create } from 'zustand';

import type { Viewport } from '../globe/viewport';
import { LAYERS } from '../layers/registry';

export interface Selected {
  id: string;
  layer: string;
  name: string;
  lat: number;
  lon: number;
  alt?: number | null;
  props: Record<string, unknown>;
}

export interface FlyTarget {
  lat: number;
  lon: number;
  alt?: number;
  /** camera height in metres */
  height?: number;
}

export type TimeWindow = '1h' | '24h' | '7d' | '30d';

interface State {
  visible: Record<string, boolean>;
  counts: Record<string, number>;
  selected: Selected | null;
  flyTo: FlyTarget | null;
  timeWindow: TimeWindow;
  metersPerPixel: number | null;
  clockIso: string | null;
  viewport: Viewport | null;
  setLayerVisible: (id: string, on: boolean) => void;
  setCount: (id: string, n: number) => void;
  select: (s: Selected | null) => void;
  requestFlyTo: (t: FlyTarget | null) => void;
  setTimeWindow: (w: TimeWindow) => void;
  setMetersPerPixel: (m: number | null) => void;
  setClockIso: (iso: string | null) => void;
  setViewport: (v: Viewport | null) => void;
}

export const useStore = create<State>((set) => ({
  visible: Object.fromEntries(LAYERS.map((l) => [l.id, l.defaultVisible])),
  counts: {},
  selected: null,
  flyTo: null,
  timeWindow: '24h',
  metersPerPixel: null,
  clockIso: null,
  viewport: null,
  setLayerVisible: (id, on) => set((s) => ({ visible: { ...s.visible, [id]: on } })),
  setCount: (id, n) => set((s) => (s.counts[id] === n ? s : { counts: { ...s.counts, [id]: n } })),
  select: (selected) => set({ selected }),
  requestFlyTo: (flyTo) => set({ flyTo }),
  setTimeWindow: (timeWindow) => set({ timeWindow }),
  setMetersPerPixel: (metersPerPixel) => set({ metersPerPixel }),
  setClockIso: (clockIso) => set({ clockIso }),
  setViewport: (viewport) => set({ viewport }),
}));
