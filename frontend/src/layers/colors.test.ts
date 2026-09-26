import { describe, expect, it } from 'vitest';

import {
  altitudeColor,
  categoricalColor,
  colorFor,
  divergingColor,
  GROUND_COLOR,
  hexToRgb,
  rgbToHex,
  sequentialColor,
  UNKNOWN_ALTITUDE_COLOR,
} from './colors';

function hue(hex: string): number {
  const { r, g, b } = hexToRgb(hex);
  const max = Math.max(r, g, b);
  const d = max - Math.min(r, g, b);
  if (d === 0) return 0;
  const h = max === r ? ((g - b) / d + 6) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return h * 60;
}

const lightness = (hex: string) => {
  const { r, g, b } = hexToRgb(hex);
  return (Math.max(r, g, b) + Math.min(r, g, b)) / 510;
};

describe('colors', () => {
  it('round-trips hex', () => {
    expect(rgbToHex(hexToRgb('#22d3ee'))).toBe('#22d3ee');
    expect(rgbToHex(hexToRgb('#fff'))).toBe('#ffffff');
  });

  it('categorical colours are deterministic and stay valid hex', () => {
    const a = categoricalColor('#22d3ee', 'tanker');
    expect(a).toBe(categoricalColor('#22d3ee', 'tanker'));
    expect(a).toMatch(/^#[0-9a-f]{6}$/);
    expect(categoricalColor('#22d3ee', 'cargo')).not.toBe(a);
  });

  it('sequential colours get brighter with t', () => {
    const lo = hexToRgb(sequentialColor('#facc15', 0));
    const hi = hexToRgb(sequentialColor('#facc15', 1));
    expect(lo.r + lo.g + lo.b).toBeLessThan(hi.r + hi.g + hi.b);
  });

  it('diverging goes from blue to red', () => {
    const cold = hexToRgb(divergingColor(0));
    const warm = hexToRgb(divergingColor(1));
    expect(cold.b).toBeGreaterThan(cold.r);
    expect(warm.r).toBeGreaterThan(warm.b);
  });

  it('colorFor falls back to the base colour when the attribute is missing', () => {
    const rule = { base: '#facc15', attribute: 'magnitude', scale: 'sequential' as const };
    expect(colorFor(rule, {})).toBe('#facc15');
    expect(colorFor(rule, { magnitude: 7 })).not.toBe(colorFor(rule, { magnitude: 2 }));
  });

  it('sequential never runs out to white, and stays monotonic at the top', () => {
    // #60a5fa has lightness 0.68: the old formula overflowed to 1.03 and clamped everything past ~12 km to white
    expect(sequentialColor('#60a5fa', 1)).not.toBe('#ffffff');
    expect(lightness(sequentialColor('#60a5fa', 1))).toBeLessThanOrEqual(0.901);
    expect(sequentialColor('#60a5fa', 0.9)).not.toBe(sequentialColor('#60a5fa', 1));
  });

  it('colorFor falls back to the base colour for non-numeric values', () => {
    const rule = { base: '#facc15', attribute: 'magnitude', scale: 'sequential' as const };
    expect(colorFor(rule, { magnitude: 'n/a' })).toBe('#facc15');
  });
});

describe('altitude colours', () => {
  const rule = { base: '#60a5fa', attribute: 'altitude_m', scale: 'sequential' as const };

  it('runs through several hues from the ground up to cruise levels', () => {
    const hues = [0, 1830, 3350, 6000, 9000, 12_190].map((m) => hue(altitudeColor(m)));
    for (let i = 1; i < hues.length; i++) expect(hues[i]!).toBeGreaterThan(hues[i - 1]!);
    expect(hues[0]!).toBeLessThan(40); // red-orange near the ground
    expect(hues[hues.length - 1]!).toBeGreaterThan(280); // magenta at cruise
  });

  it('clamps below zero and above the top of the ramp, and stays valid hex', () => {
    expect(altitudeColor(-50)).toBe(altitudeColor(0));
    expect(altitudeColor(15_000)).toBe(altitudeColor(13_000));
    expect(altitudeColor(10_000)).toMatch(/^#[0-9a-f]{6}$/);
    expect(altitudeColor(10_000)).toBe(altitudeColor(10_010)); // quantised
  });

  it('keeps every airborne level visible on dark imagery', () => {
    for (let m = 0; m <= 13_000; m += 500) expect(lightness(altitudeColor(m))).toBeGreaterThan(0.45);
  });

  it('gives ground and unknown altitude their own colours', () => {
    expect(colorFor(rule, { altitude_m: null, on_ground: true })).toBe(GROUND_COLOR);
    expect(colorFor(rule, { altitude_m: 11_000, on_ground: true })).toBe(GROUND_COLOR);
    expect(colorFor(rule, { altitude_m: null })).toBe(UNKNOWN_ALTITUDE_COLOR);
    expect(colorFor(rule, {})).toBe(UNKNOWN_ALTITUDE_COLOR);
    expect(colorFor(rule, { altitude_m: 'high' })).toBe(UNKNOWN_ALTITUDE_COLOR);
    const airborne = new Set([0, 3000, 6000, 9000, 12_000].map((m) => altitudeColor(m)));
    expect(airborne.has(GROUND_COLOR) || airborne.has(UNKNOWN_ALTITUDE_COLOR)).toBe(false);
  });

  it('uses the fallback (the feature height) only when the attribute is missing', () => {
    expect(colorFor(rule, {}, 9000)).toBe(altitudeColor(9000));
    expect(colorFor(rule, { altitude_m: 3000 }, 9000)).toBe(altitudeColor(3000));
    expect(colorFor(rule, { altitude_m: null }, 9000)).toBe(UNKNOWN_ALTITUDE_COLOR);
  });
});
