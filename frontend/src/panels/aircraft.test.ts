import { describe, expect, it } from 'vitest';

import { AIRCRAFT_KEYS, distanceSinceKm, isAircraft, lookupValue, squawkAlert } from './aircraft';

describe('aircraft inspector helpers', () => {
  it('flags the special squawk codes only', () => {
    expect(squawkAlert('7700')).toBe('emergency');
    expect(squawkAlert('7600')).toBe('radio failure');
    expect(squawkAlert('7500')).toBe('hijack');
    expect(squawkAlert(' 7700 ')).toBe('emergency');
    expect([squawkAlert('1000'), squawkAlert(null), squawkAlert('')]).toEqual([null, null, null]);
  });

  it('runs lookup modules with the ICAO24 address, not the callsign', () => {
    const props = { icao24: '4ca334', callsign: 'RYR4TX', mmsi: 1 };
    expect(lookupValue('aircraft', 'RYR4TX', props)).toBe('4ca334');
    expect(lookupValue('aircraft', 'RYR4TX', {})).toBe('RYR4TX');
    expect(lookupValue('vessel', 'EVER GIVEN', { mmsi: 353136000 })).toBe('353136000');
    expect(lookupValue('domain', 'example.com', props)).toBe('example.com');
  });

  it('recognises aircraft by entity type or by an aviation feature with an ICAO24', () => {
    expect(isAircraft('aircraft', {})).toBe(true);
    expect(isAircraft('', { layer: 'aviation', icao24: '4ca334' })).toBe(true);
    expect(isAircraft('vessel', { layer: 'maritime' })).toBe(false);
  });

  it('estimates how far an aircraft moved since its last position', () => {
    expect(distanceSinceKm(450, 120)).toBeCloseTo(27.78, 2);
    expect(distanceSinceKm(null, 120)).toBeNull();
    expect(distanceSinceKm(450, 0)).toBeNull();
  });

  it('hides the formatted keys from the raw dump', () => {
    for (const k of ['altitude_m', 'speed', 'heading', 'vertical_rate_fpm', 'squawk', 'icao24', 'time']) expect(AIRCRAFT_KEYS.has(k)).toBe(true);
    expect(AIRCRAFT_KEYS.has('military')).toBe(false);
  });
});
