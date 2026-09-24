export function formatCoord(lat: number, lon: number): string {
  const f = (v: number, pos: string, neg: string) => `${Math.abs(v).toFixed(4)}°${v >= 0 ? pos : neg}`;
  return `${f(lat, 'N', 'S')} ${f(lon, 'E', 'W')}`;
}

export function formatDistance(m: number): string {
  if (m >= 1_000_000) return `${(m / 1_000_000).toFixed(1)} Mm`;
  if (m >= 1000) return `${(m / 1000).toFixed(m >= 100_000 ? 0 : 1)} km`;
  if (m >= 1) return `${m.toFixed(0)} m`;
  return `${(m * 100).toFixed(0)} cm`;
}

export function formatAltitude(m: number | null | undefined): string {
  if (m === null || m === undefined) return '—';
  if (Math.abs(m) >= 1000) return `${(m / 1000).toFixed(1)} km`;
  return `${m.toFixed(0)} m`;
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}
