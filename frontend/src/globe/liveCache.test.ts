import { describe, expect, it } from 'vitest';

import type { LiveDelta } from '../api/types';
import { dropExpired, isExpired, LiveCache, liveMaxAgeS, mergeDelta, parseTs, ServerClock } from './liveCache';
import type { RenderFeature } from './renderers/types';

const T0 = Date.parse('2026-09-24T10:00:00Z');
const iso = (ms: number) => new Date(ms).toISOString();

function delta(id: string, atMs: number, extra: Partial<LiveDelta> = {}): LiveDelta {
  return { t: 'track', id, lon: 8.5, lat: 50, alt: 10_000, hdg: 90, spd: 450, ts: iso(atMs), ...extra };
}

function feature(id: string, atMs: number | undefined, props: Record<string, unknown> = {}): RenderFeature {
  return { id, layer: 'aviation', lon: 1, lat: 2, alt: 3000, name: id, props: { layer: 'aviation', ...props }, ts: atMs };
}

describe('mergeDelta', () => {
  it('merges props over the previous ones instead of replacing them', () => {
    const prev = feature('a', T0, { altitude_m: 3000, precision: 'exact', entity_type: 'aircraft', registration: 'D-AIBL' });
    const next = mergeDelta('aviation', prev, delta('a', T0 + 5000, { alt: 3200, props: { altitude_m: 3200 } }))!;
    expect(next.props).toMatchObject({ altitude_m: 3200, precision: 'exact', entity_type: 'aircraft', registration: 'D-AIBL' });
    expect(next.props).toMatchObject({ heading: 90, speed: 450, time: iso(T0 + 5000) });
    expect(next).toMatchObject({ alt: 3200, ts: T0 + 5000, name: 'a' });
  });

  it('lets an explicit null through (an aircraft that landed has no altitude)', () => {
    const prev = feature('a', T0, { altitude_m: 300, on_ground: false });
    const next = mergeDelta('aviation', prev, delta('a', T0 + 1000, { alt: null, props: { altitude_m: null, on_ground: true } }))!;
    expect(next.props).toMatchObject({ altitude_m: null, on_ground: true });
    expect(next.alt).toBeNull();
  });

  it('keeps heading and speed when the delta does not carry them', () => {
    const prev = feature('e', T0, { heading: 12, speed: 3 });
    const next = mergeDelta('aviation', prev, { t: 'event', id: 'e', lon: 0, lat: 0, alt: null, ts: iso(T0 + 1) })!;
    expect(next.props).toMatchObject({ heading: 12, speed: 3 });
  });

  it('ignores a delta older than what is shown', () => {
    const prev = feature('a', T0);
    expect(mergeDelta('aviation', prev, delta('a', T0 - 1000))).toBeNull();
    expect(mergeDelta('aviation', prev, delta('a', T0))).not.toBeNull(); // same fix again is harmless
  });
});

describe('LiveCache', () => {
  const at = (receivedAt: number) => ({ receivedAt, serverNow: receivedAt });

  it('applies deltas, merges repeats and marks changed ids dirty until taken', () => {
    const cache = new LiveCache('aviation', 1200);
    expect(cache.applyDeltas([delta('a', T0, { props: { registration: 'D-AIBL' } }), delta('b', T0)], at(T0))).toBe(2);
    expect(cache.applyDeltas([delta('a', T0 + 5000, { props: { altitude_m: 10_100 } })], at(T0 + 5000))).toBe(1);
    expect(cache.size).toBe(2);
    expect(cache.isDirty('a')).toBe(true);
    const dirty = cache.takeDirty();
    expect(dirty.map((f) => f.id).sort()).toEqual(['a', 'b']);
    expect(cache.get('a')?.props).toMatchObject({ registration: 'D-AIBL', altitude_m: 10_100 });
    expect(cache.takeDirty()).toEqual([]);
  });

  it('does not count or redraw older deltas', () => {
    const cache = new LiveCache('aviation', 1200);
    cache.applyDeltas([delta('a', T0, { lon: 10 })], at(T0));
    cache.takeDirty();
    expect(cache.applyDeltas([delta('a', T0 - 2000, { lon: 9 })], at(T0 + 100))).toBe(0);
    expect(cache.get('a')?.lon).toBe(10);
    expect(cache.takeDirty()).toEqual([]);
  });

  it('refuses deltas that are already older than the max age', () => {
    const cache = new LiveCache('aviation', 60);
    expect(cache.applyDeltas([delta('a', T0 - 61_000)], at(T0))).toBe(0);
    expect(cache.size).toBe(0);
  });

  it('sweeps features older than the max age on the server clock', () => {
    const cache = new LiveCache('aviation', 1200);
    cache.applyDeltas([delta('old', T0), delta('new', T0 + 600_000)], at(T0 + 600_000));
    expect(cache.sweep(T0 + 1_200_000)).toEqual([]); // exactly max age: still shown
    expect(cache.sweep(T0 + 1_200_001)).toEqual(['old']);
    expect(cache.isDirty('old')).toBe(false);
    expect(cache.values().map((f) => f.id)).toEqual(['new']);
    expect(new LiveCache('x', null).sweep(Number.MAX_SAFE_INTEGER)).toEqual([]);
  });

  it('never expires features without a time', () => {
    const cache = new LiveCache('aviation', 10);
    cache.applySnapshot([feature('untimed', undefined)], { requestedAt: T0, serverNow: T0 });
    expect(cache.sweep(T0 + 3_600_000)).toEqual([]);
  });

  it('treats a snapshot as the truth as of its request, keeping what arrived live since', () => {
    const cache = new LiveCache('aviation', 1200);
    cache.applySnapshot([feature('gone', T0), feature('stays', T0)], { requestedAt: T0, serverNow: T0 });
    cache.applyDeltas([delta('seen-before-refetch', T0 + 1000)], at(T0 + 1000));
    cache.applyDeltas([delta('seen-during-refetch', T0 + 3000)], at(T0 + 3000));
    const removed = cache.applySnapshot([feature('stays', T0 + 2000)], { requestedAt: T0 + 2000, serverNow: T0 + 4000 });
    expect(removed.sort()).toEqual(['gone', 'seen-before-refetch']);
    expect(cache.values().map((f) => f.id).sort()).toEqual(['seen-during-refetch', 'stays']);
    expect(cache.takeDirty()).toEqual([]); // the caller redraws the whole layer
  });

  it('keeps a live position newer than the snapshot, filling in the props deltas do not carry', () => {
    const cache = new LiveCache('aviation', 1200);
    cache.applyDeltas([delta('a', T0 + 5000, { lon: 20, props: { altitude_m: 9000 } })], at(T0 + 5000));
    cache.applySnapshot([feature('a', T0, { altitude_m: 8000, operator: 'Lufthansa' })], { requestedAt: T0 + 4000, serverNow: T0 + 6000 });
    expect(cache.get('a')).toMatchObject({ lon: 20, ts: T0 + 5000 });
    expect(cache.get('a')?.props).toMatchObject({ altitude_m: 9000, operator: 'Lufthansa' });
  });

  it('takes the snapshot row when it is at least as new as the cached one', () => {
    const cache = new LiveCache('aviation', 1200);
    cache.applyDeltas([delta('a', T0, { lon: 20 })], at(T0));
    cache.applySnapshot([feature('a', T0 + 1000)], { requestedAt: T0 + 2000, serverNow: T0 + 2000 });
    expect(cache.get('a')).toMatchObject({ lon: 1, ts: T0 + 1000 });
  });

  it('filters stale snapshot rows by the max age', () => {
    const cache = new LiveCache('aviation', 1200);
    cache.applySnapshot([feature('fresh', T0 - 60_000), feature('stale', T0 - 1_300_000)], { requestedAt: T0, serverNow: T0 });
    expect(cache.values().map((f) => f.id)).toEqual(['fresh']);
  });
});

describe('expiry helpers', () => {
  it('parses times', () => {
    expect(parseTs('2026-09-24T10:00:00Z')).toBe(T0);
    expect(parseTs('2026-09-24T12:00:00+02:00')).toBe(T0);
    expect(parseTs(T0)).toBe(T0);
    expect([parseTs(''), parseTs('soon'), parseTs(null), parseTs(Number.NaN)]).toEqual([undefined, undefined, undefined, undefined]);
  });

  it('drops expired snapshot features only when the layer has a max age', () => {
    const feats = [feature('a', T0 - 10_000), feature('b', T0 - 100), feature('c', undefined)];
    expect(dropExpired(feats, 5, T0).map((f) => f.id)).toEqual(['b', 'c']);
    expect(dropExpired(feats, null, T0)).toBe(feats);
    expect(isExpired({ ts: T0 - 5001 }, 5, T0)).toBe(true);
  });

  it('narrows the max age by the time window', () => {
    expect(liveMaxAgeS(1200, '24h')).toBe(1200);
    expect(liveMaxAgeS(21_600, '1h')).toBe(3600);
    expect(liveMaxAgeS(null, '7d')).toBe(604_800);
  });

  it('measures time on the server clock', () => {
    const clock = new ServerClock();
    expect(clock.now(T0)).toBe(T0);
    clock.observe('2026-09-24T10:00:30Z', T0); // server runs 30 s ahead of this browser
    expect(clock.skewMs).toBe(30_000);
    expect(clock.now(T0 + 1000)).toBe(T0 + 31_000);
    clock.observe(null, T0);
    clock.observe('not a time', T0);
    expect(clock.skewMs).toBe(30_000);
  });
});
