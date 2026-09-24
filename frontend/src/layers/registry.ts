import { LAYERS } from './generated';
import type { LayerSpec } from './types';

export { LAYERS };

const byId = new Map(LAYERS.map((l) => [l.id, l]));

export function getLayer(id: string): LayerSpec | undefined {
  return byId.get(id);
}

export const GROUP_LABELS: Record<LayerSpec['group'], string> = {
  live: 'Live',
  events: 'Events',
  static: 'Reference',
  investigation: 'Investigation',
};

/** Poll interval in ms for a layer's `update` value; null means no polling (stream/static/on demand). */
export function pollIntervalMs(update: string): number | null {
  const m = /^poll:(\d+)?(m|h|d|hourly|daily|weekly)$/.exec(update);
  if (!m) return null;
  const n = m[1] ? Number(m[1]) : 1;
  const unit = m[2] ?? 'h';
  const seconds = { m: 60, h: 3600, d: 86400, hourly: 3600, daily: 86400, weekly: 604800 }[unit] ?? 3600;
  return n * seconds * 1000;
}
