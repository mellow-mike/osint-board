import { create } from 'zustand';

import type { StreamState } from '../api/types';
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
  /** epoch ms of the shown position/observation, when known */
  ts?: number;
  /** A live feature that expired from its layer (no update within the layer's max age): what is shown is its last state. */
  stale?: boolean;
}

/** Fields a live update may change on the selected feature. */
export type SelectedPatch = Partial<Omit<Selected, 'id' | 'layer'>>;

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
  /** server clock minus local clock (ms), from the last features response: ages are measured on the server's clock */
  clockSkewMs: number;
  /** live stream status while any streamed layer is shown; null when no stream is open */
  stream: StreamState | null;
  setLayerVisible: (id: string, on: boolean) => void;
  setCount: (id: string, n: number) => void;
  select: (s: Selected | null) => void;
  /** Patch the selection if it is still `layer`/`id` (live updates race with the user clicking elsewhere). */
  updateSelected: (layer: string, id: string, patch: SelectedPatch) => void;
  requestFlyTo: (t: FlyTarget | null) => void;
  setTimeWindow: (w: TimeWindow) => void;
  setMetersPerPixel: (m: number | null) => void;
  setClockIso: (iso: string | null) => void;
  setViewport: (v: Viewport | null) => void;
  setClockSkew: (ms: number) => void;
  setStream: (s: StreamState | null) => void;
}

function sameStream(a: StreamState | null, b: StreamState | null): boolean {
  if (a === null || b === null) return a === b;
  return a.state === b.state && (a.state !== 'down' || (b.state === 'down' && a.message === b.message));
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
  clockSkewMs: 0,
  stream: null,
  setLayerVisible: (id, on) => set((s) => ({ visible: { ...s.visible, [id]: on } })),
  setCount: (id, n) => set((s) => (s.counts[id] === n ? s : { counts: { ...s.counts, [id]: n } })),
  select: (selected) => set({ selected }),
  updateSelected: (layer, id, patch) =>
    set((s) => (s.selected && s.selected.id === id && s.selected.layer === layer ? { selected: { ...s.selected, ...patch } } : s)),
  requestFlyTo: (flyTo) => set({ flyTo }),
  setTimeWindow: (timeWindow) => set({ timeWindow }),
  setMetersPerPixel: (metersPerPixel) => set({ metersPerPixel }),
  setClockIso: (clockIso) => set({ clockIso }),
  setViewport: (viewport) => set({ viewport }),
  // sub-second changes are measurement noise; skipping them avoids re-rendering every age readout per response
  setClockSkew: (ms) => set((s) => (Math.abs(s.clockSkewMs - ms) < 1000 ? s : { clockSkewMs: ms })),
  setStream: (stream) => set((s) => (sameStream(s.stream, stream) ? s : { stream })),
}));
