import { describe, expect, it } from 'vitest';

import {
  formatAge,
  formatAltitude,
  formatDuration,
  formatFeet,
  formatFlightLevel,
  formatHeading,
  formatSpeedKt,
  formatVerticalRate,
} from './format';

describe('aviation formats', () => {
  it('feet and flight levels from metres', () => {
    expect(formatFeet(11_278)).toBe('37,001 ft');
    expect(formatFeet(0)).toBe('0 ft');
    expect(formatFlightLevel(11_278)).toBe('FL370');
    expect(formatFlightLevel(1524)).toBe('FL050');
    expect(formatFlightLevel(-100)).toBe('FL000');
    expect(formatAltitude(11_278)).toBe('11.3 km');
  });

  it('speed, track and vertical rate', () => {
    expect(formatSpeedKt(452)).toBe('452 kt · 837 km/h');
    expect(formatHeading(274)).toBe('274° W');
    expect(formatHeading(359.6)).toBe('0° N');
    expect(formatHeading(-45)).toBe('315° NW');
    expect(formatHeading(135)).toBe('135° SE');
    expect(formatVerticalRate(1600)).toBe('+1,600 ft/min');
    expect(formatVerticalRate(-832)).toBe('−832 ft/min');
    expect(formatVerticalRate(0)).toBe('level');
    expect(formatVerticalRate(-63)).toBe('level');
    expect(formatVerticalRate(64)).toBe('+64 ft/min');
  });

  it('missing values render as a dash', () => {
    for (const f of [formatFeet, formatFlightLevel, formatSpeedKt, formatHeading, formatVerticalRate, formatAge, formatDuration]) {
      expect(f(null)).toBe('—');
      expect(f(undefined)).toBe('—');
      expect(f(Number.NaN)).toBe('—');
    }
  });

  it('ages and durations', () => {
    expect(formatAge(0.4)).toBe('just now');
    expect(formatAge(-3)).toBe('just now'); // clock skew never shows a negative age
    expect(formatAge(42.9)).toBe('42 s ago');
    expect(formatAge(185)).toBe('3 min ago');
    expect(formatAge(7200)).toBe('2 h ago');
    expect(formatAge(7500)).toBe('2 h 5 min ago');
    expect(formatAge(3 * 86_400 + 5)).toBe('3 d ago');
    expect(formatDuration(1200)).toBe('20 min');
    expect(formatDuration(21_600)).toBe('6 h');
  });
});
