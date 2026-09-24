// Colour rules are pure so they can be unit-tested and shared with legends.

import type { ColorScale } from './types';

export interface Rgb {
  r: number;
  g: number;
  b: number;
}

export function hexToRgb(hex: string): Rgb {
  const h = hex.replace('#', '');
  const n = parseInt(h.length === 3 ? h.split('').map((c) => c + c).join('') : h, 16);
  return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
}

export function rgbToHex({ r, g, b }: Rgb): string {
  const c = (v: number) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0');
  return `#${c(r)}${c(g)}${c(b)}`;
}

function rgbToHsl({ r, g, b }: Rgb): [number, number, number] {
  const rn = r / 255, gn = g / 255, bn = b / 255;
  const max = Math.max(rn, gn, bn), min = Math.min(rn, gn, bn);
  const l = (max + min) / 2;
  if (max === min) return [0, 0, l];
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h: number;
  if (max === rn) h = ((gn - bn) / d + (gn < bn ? 6 : 0)) / 6;
  else if (max === gn) h = ((bn - rn) / d + 2) / 6;
  else h = ((rn - gn) / d + 4) / 6;
  return [h, s, l];
}

function hslToRgb(h: number, s: number, l: number): Rgb {
  const f = (n: number) => {
    const k = (n + h * 12) % 12;
    const a = s * Math.min(l, 1 - l);
    return l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1));
  };
  return { r: f(0) * 255, g: f(8) * 255, b: f(4) * 255 };
}

export function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** Deterministic per-category colour: rotate hue around the layer base colour, keep it in the family. */
export function categoricalColor(baseHex: string, key: string): string {
  const [h, s, l] = rgbToHsl(hexToRgb(baseHex));
  const shift = ((hashString(key) % 9) - 4) * 0.035; // ±14% hue swing around the base
  const lum = Math.min(0.85, Math.max(0.35, l + (((hashString(key + '#') % 5) - 2) * 0.05)));
  return rgbToHex(hslToRgb((h + shift + 1) % 1, Math.max(0.45, s), lum));
}

/** Sequential: dim → base → bright as t goes 0 → 1. */
export function sequentialColor(baseHex: string, t: number): string {
  const [h, s, l] = rgbToHsl(hexToRgb(baseHex));
  const tt = Math.max(0, Math.min(1, t));
  return rgbToHex(hslToRgb(h, s, 0.25 + tt * Math.max(0.2, l + 0.35 - 0.25)));
}

/** Diverging: cold blue (t=0) → neutral (0.5) → warm red (1). */
export function divergingColor(t: number): string {
  const tt = Math.max(0, Math.min(1, t));
  return tt < 0.5 ? rgbToHex(hslToRgb(0.6, 0.7, 0.35 + tt * 0.6)) : rgbToHex(hslToRgb(0.0, 0.75, 0.65 - (tt - 0.5) * 0.6));
}

export interface ColorRule {
  base: string;
  attribute: string;
  scale: ColorScale;
  /** min/max for sequential & diverging normalisation */
  domain?: [number, number];
}

const DEFAULT_DOMAINS: Record<string, [number, number]> = {
  magnitude: [1, 8],
  frp: [0, 100],
  altitude_m: [0, 13_000],
  goldstein: [-10, 10],
  severity: [0, 10],
  wind_speed: [0, 30],
};

export function colorFor(rule: ColorRule, props: Record<string, unknown>): string {
  const raw = props[rule.attribute];
  if (raw === undefined || raw === null) return rule.base;
  if (rule.scale === 'categorical') return categoricalColor(rule.base, String(raw));
  const [lo, hi] = rule.domain ?? DEFAULT_DOMAINS[rule.attribute] ?? [0, 1];
  const t = (Number(raw) - lo) / (hi - lo || 1);
  return rule.scale === 'sequential' ? sequentialColor(rule.base, t) : divergingColor(t);
}
