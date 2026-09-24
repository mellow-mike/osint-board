import { describe, expect, it } from 'vitest';

import { categoricalColor, colorFor, divergingColor, hexToRgb, rgbToHex, sequentialColor } from './colors';

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
});
