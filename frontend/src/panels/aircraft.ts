// Pure helpers for the inspector's aircraft section (props are the aviation emit's meta: modules/adsb.py to_emit).

/** Props the aircraft section presents with units; the generic key/value dump skips them. */
export const AIRCRAFT_KEYS: ReadonlySet<string> = new Set([
  'callsign',
  'icao24',
  'registration',
  'type_code',
  'type_desc',
  'operator',
  'altitude_m',
  'alt_geom_m',
  'alt_baro_m',
  'alt_source',
  'heading',
  'speed',
  'vertical_rate_fpm',
  'squawk',
  'emergency',
  'source',
  'position_source',
  'mlat',
  'on_ground',
  'time',
]);

/** Special-purpose transponder codes. */
export const SQUAWK_ALERTS: Readonly<Record<string, string>> = {
  '7500': 'hijack',
  '7600': 'radio failure',
  '7700': 'emergency',
};

export const POSITION_SOURCE_LABELS: Readonly<Record<string, string>> = {
  adsb: 'ADS-B',
  adsr: 'ADS-R',
  adsc: 'ADS-C',
  tisb: 'TIS-B',
  mlat: 'MLAT',
  other: 'other',
};

/** An aircraft's position older than this is flagged in the inspector (at cruise speed that is already ~15 km). */
export const AIRCRAFT_OLD_POSITION_S = 60;

export function isAircraft(entityType: string, props: Record<string, unknown>): boolean {
  return entityType === 'aircraft' || (props['layer'] === 'aviation' && typeof props['icao24'] === 'string');
}

export function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

export function text(v: unknown): string | null {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : typeof v === 'number' ? String(v) : null;
}

/** The label of a special squawk code, or null for an ordinary one. */
export function squawkAlert(squawk: unknown): string | null {
  const s = text(squawk);
  return s !== null ? (SQUAWK_ALERTS[s] ?? null) : null;
}

/** Kilometres covered at `kt` knots in `seconds`, or null when either is unknown. */
export function distanceSinceKm(kt: number | null, seconds: number | null): number | null {
  if (kt === null || seconds === null || seconds <= 0) return null;
  return (kt * 1.852 * seconds) / 3600;
}

/**
 * The value lookup modules expect for an entity: an aircraft's ICAO24 address (its callsign is only the flight),
 * a vessel's MMSI, otherwise the display name.
 */
export function lookupValue(entityType: string, name: string, props: Record<string, unknown>): string {
  if (entityType === 'aircraft') return text(props['icao24']) ?? name;
  if (entityType === 'vessel') return text(props['mmsi']) ?? name;
  return name;
}
