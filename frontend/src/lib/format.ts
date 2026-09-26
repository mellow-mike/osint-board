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

const M_TO_FT = 1 / 0.3048;
const KT_TO_KMH = 1.852;
const int = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

function isNum(v: number | null | undefined): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

/** Metres as feet: `36,975 ft`. */
export function formatFeet(m: number | null | undefined): string {
  return isNum(m) ? `${int.format(m * M_TO_FT)} ft` : '—';
}

/** Metres (pressure altitude) as a flight level: 11 278 m → `FL370`. */
export function formatFlightLevel(m: number | null | undefined): string {
  if (!isNum(m)) return '—';
  const fl = Math.max(0, Math.round((m * M_TO_FT) / 100));
  return `FL${String(fl).padStart(3, '0')}`;
}

/** Ground speed in knots, with km/h: `452 kt · 837 km/h`. */
export function formatSpeedKt(kt: number | null | undefined): string {
  return isNum(kt) ? `${int.format(kt)} kt · ${int.format(kt * KT_TO_KMH)} km/h` : '—';
}

/** Vertical rate: `+1,600 ft/min`, `−832 ft/min`; within one readsb step (64 ft/min) of zero it is `level`. */
export function formatVerticalRate(fpm: number | null | undefined): string {
  if (!isNum(fpm)) return '—';
  if (Math.abs(fpm) < 64) return 'level';
  return `${fpm > 0 ? '+' : '−'}${int.format(Math.abs(fpm))} ft/min`;
}

const COMPASS = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'] as const;

/** Track or heading in degrees true with its compass point: `274° W`. */
export function formatHeading(deg: number | null | undefined): string {
  if (!isNum(deg)) return '—';
  const d = ((Math.round(deg) % 360) + 360) % 360;
  return `${d}° ${COMPASS[Math.round(d / 45) % 8]}`;
}

/** A span of seconds, coarsest two units: `42 s`, `3 min`, `2 h 5 min`, `3 d`. */
export function formatDuration(seconds: number | null | undefined): string {
  if (!isNum(seconds)) return '—';
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86_400) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return m ? `${h} h ${m} min` : `${h} h`;
  }
  return `${Math.floor(s / 86_400)} d`;
}

/** How long ago, from an age in seconds: `just now`, `42 s ago`, `3 min ago`, `2 h 5 min ago`, `3 d ago`. */
export function formatAge(seconds: number | null | undefined): string {
  if (!isNum(seconds)) return '—';
  return seconds < 1 ? 'just now' : `${formatDuration(seconds)} ago`;
}
