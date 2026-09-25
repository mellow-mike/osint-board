import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { openStream, parseFrame } from './client';
import type { LiveBatchFrame, LiveDeltaFrame, StreamErrorFrame, StreamState } from './types';

const plane = {
  t: 'track',
  id: 'aviation:4ca334',
  lon: 8.55,
  lat: 50.03,
  alt: 10668.0,
  hdg: 271.5,
  spd: 452.0,
  ts: '2026-09-24T10:00:00+00:00',
  name: 'RYR4TX',
  props: { altitude_m: 10668.0, precision: 'exact', geo_source: 'adsb.lol', entity_type: 'aircraft' },
} as const;

const batch = (items: unknown[], layer = 'aviation'): string => JSON.stringify({ t: 'batch', layer, items } satisfies Omit<LiveBatchFrame, 'items'> & { items: unknown[] });

describe('parseFrame', () => {
  it('unpacks a batch into validated deltas for its layer', () => {
    const frame = parseFrame(batch([plane, { ...plane, id: 'aviation:3c6444', alt: null, hdg: null, spd: null }]));
    expect(frame.kind).toBe('deltas');
    if (frame.kind !== 'deltas') return;
    expect(frame.layer).toBe('aviation');
    expect(frame.invalid).toBe(0);
    expect(frame.deltas).toHaveLength(2);
    expect(frame.deltas[0]).toMatchObject({ id: 'aviation:4ca334', alt: 10668, hdg: 271.5, spd: 452, name: 'RYR4TX' });
    expect(frame.deltas[0]?.props?.['entity_type']).toBe('aircraft');
    expect(frame.deltas[1]).toMatchObject({ alt: null, hdg: null, spd: null });
  });

  it('accepts a legacy single delta that names its layer', () => {
    const legacy: LiveDeltaFrame = { ...plane, layer: 'aviation', props: {} };
    const frame = parseFrame(JSON.stringify(legacy));
    expect(frame).toMatchObject({ kind: 'deltas', layer: 'aviation', invalid: 0 });
    if (frame.kind === 'deltas') expect(frame.deltas[0]).not.toHaveProperty('layer');
  });

  it('never guesses a layer: frames without one are dropped', () => {
    expect(parseFrame(JSON.stringify(plane))).toEqual({ kind: 'ignored', reason: 'no_layer' });
    expect(parseFrame(JSON.stringify({ t: 'batch', items: [plane] }))).toEqual({ kind: 'ignored', reason: 'no_layer' });
  });

  it('drops frames for layers this socket did not subscribe to', () => {
    const subscribed = new Set(['maritime']);
    expect(parseFrame(batch([plane]), subscribed)).toEqual({ kind: 'ignored', reason: 'not_subscribed' });
    expect(parseFrame(batch([plane], 'maritime'), subscribed).kind).toBe('deltas');
  });

  it('surfaces server error frames', () => {
    const err: StreamErrorFrame = { type: 'error', message: 'live streaming needs redis' };
    expect(parseFrame(JSON.stringify(err))).toEqual({ kind: 'error', message: 'live streaming needs redis' });
    expect(parseFrame(JSON.stringify({ type: 'error' }))).toEqual({ kind: 'error', message: 'live stream error' });
  });

  it('skips items without an id, a real position or a parseable time', () => {
    const frame = parseFrame(
      batch([
        plane,
        { ...plane, id: '' },
        { ...plane, lon: null },
        { ...plane, lat: 91 },
        { ...plane, lon: 'NaN' },
        { ...plane, ts: 'yesterday' },
        { ...plane, t: 'remove' },
        'garbage',
      ]),
    );
    expect(frame).toMatchObject({ kind: 'deltas', invalid: 7 });
    if (frame.kind === 'deltas') expect(frame.deltas.map((d) => d.id)).toEqual(['aviation:4ca334']);
  });

  it('keeps absent optional fields absent so the cache keeps what it has', () => {
    const bare = { t: 'event', id: plane.id, lon: plane.lon, lat: plane.lat, alt: 'high', ts: plane.ts };
    const frame = parseFrame(batch([bare]));
    if (frame.kind !== 'deltas') throw new Error('expected deltas');
    const d = frame.deltas[0]!;
    expect(d.alt).toBeNull();
    expect('hdg' in d || 'spd' in d || 'name' in d || 'props' in d).toBe(false);
  });

  it('ignores malformed and unknown frames', () => {
    expect(parseFrame('{not json')).toEqual({ kind: 'ignored', reason: 'malformed' });
    expect(parseFrame('[1,2]')).toEqual({ kind: 'ignored', reason: 'malformed' });
    expect(parseFrame(new ArrayBuffer(4))).toEqual({ kind: 'ignored', reason: 'malformed' });
    expect(parseFrame(JSON.stringify({ t: 'hello', layer: 'aviation' }))).toEqual({ kind: 'ignored', reason: 'unknown' });
    expect(parseFrame(JSON.stringify({ t: 'batch', layer: 'aviation', items: 'nope' }))).toMatchObject({ kind: 'deltas', deltas: [] });
  });
});

/** Just enough of a browser WebSocket to drive openStream. */
class FakeSocket {
  static all: FakeSocket[] = [];
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(readonly url: string) {
    FakeSocket.all.push(this);
  }
  close(): void {
    this.onclose?.();
  }
  receive(data: unknown): void {
    this.onmessage?.({ data });
  }
}

describe('openStream', () => {
  beforeEach(() => {
    FakeSocket.all = [];
    vi.useFakeTimers();
    vi.stubGlobal('window', { location: { protocol: 'http:', host: 'localhost:5173', origin: 'http://localhost:5173' } });
    vi.stubGlobal('WebSocket', FakeSocket);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('routes deltas by layer and logs handler errors without losing the socket', () => {
    const seen: string[] = [];
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const dispose = openStream(['aviation', 'maritime'], {
      onDeltas: (layer, deltas) => {
        if (deltas[0]?.id === 'boom') throw new Error('renderer bug');
        seen.push(`${layer}:${deltas.map((d) => d.id).join('+')}`);
      },
    });
    const ws = FakeSocket.all[0]!;
    expect(ws.url).toBe('ws://localhost:5173/api/stream?layers=aviation%2Cmaritime');
    ws.receive(batch([plane]));
    ws.receive(JSON.stringify({ ...plane, id: 'maritime:1', layer: 'maritime' }));
    ws.receive(JSON.stringify(plane)); // no layer: dropped, never attributed to the first subscription
    ws.receive(batch([{ ...plane, id: 'boom' }]));
    ws.receive(batch([{ ...plane, id: 'aviation:after' }]));
    expect(seen).toEqual(['aviation:aviation:4ca334', 'maritime:maritime:1', 'aviation:aviation:after']);
    expect(errors).toHaveBeenCalledOnce();
    dispose();
  });

  it('stays down through failing retries and refetches once a later connection is live', () => {
    const states: StreamState['state'][] = [];
    const onReconnect = vi.fn();
    const dispose = openStream(['aviation'], { onDeltas: () => {}, onReconnect, onState: (s) => states.push(s.state) });
    const first = FakeSocket.all[0]!;
    first.onopen?.();
    vi.advanceTimersByTime(3000);
    expect(states).toEqual(['connecting', 'live']);
    expect(onReconnect).not.toHaveBeenCalled(); // the first connection races the initial fetch; nothing was missed

    first.close(); // dropped
    vi.advanceTimersByTime(1000);
    const second = FakeSocket.all[1]!;
    second.onopen?.();
    second.receive(JSON.stringify({ type: 'error', message: 'live streaming needs redis' }));
    second.close();
    vi.advanceTimersByTime(2000); // backoff doubled: the failed attempt did not reset it
    expect(FakeSocket.all).toHaveLength(3);
    expect(states).toEqual(['connecting', 'live', 'connecting', 'down']);
    expect(onReconnect).not.toHaveBeenCalled();

    const third = FakeSocket.all[2]!;
    third.onopen?.();
    third.receive(batch([plane]));
    expect(states.at(-1)).toBe('live');
    expect(onReconnect).toHaveBeenCalledOnce();
    dispose();
  });

  it('stops reconnecting once disposed', () => {
    const dispose = openStream(['aviation'], { onDeltas: () => {} });
    dispose();
    vi.advanceTimersByTime(60_000);
    expect(FakeSocket.all).toHaveLength(1);
  });
});
