import { describe, expect, it } from 'vitest';

import { allowsPin } from './HaloLayer';
import { PrecisionSplitLayer } from './PrecisionSplitLayer';
import type { LayerRenderer, RenderFeature } from './types';

class MemoryRenderer implements LayerRenderer {
  readonly features = new Map<string, RenderFeature>();
  constructor(readonly layerId: string) {}
  setFeatures(features: RenderFeature[]): void {
    this.features.clear();
    for (const f of features) this.features.set(f.id, f);
  }
  upsert(f: RenderFeature): void {
    this.features.set(f.id, f);
  }
  remove(id: string): void {
    this.features.delete(id);
  }
  setVisible(): void {}
  count(): number {
    return this.features.size;
  }
  destroy(): void {}
}

function feat(id: string, precision: string | undefined, lat = 52.52, lon = 13.405): RenderFeature {
  return { id, layer: 'tor', lat, lon, alt: null, name: id, props: precision ? { precision } : {} };
}

function split() {
  const pins = new MemoryRenderer('tor');
  const halos = new MemoryRenderer('tor');
  return { pins, halos, layer: new PrecisionSplitLayer(pins, halos) };
}

describe('precision split', () => {
  it('only exact, rooftop and street (or unstated feed fixes) may be pins', () => {
    expect(['exact', 'rooftop', 'street'].every((p) => allowsPin({ precision: p }))).toBe(true);
    expect(allowsPin({})).toBe(true);
    expect(['city', 'region', 'country'].some((p) => allowsPin({ precision: p }))).toBe(false);
    expect(allowsPin({ geo_precision: 'city' })).toBe(false);
  });

  it('routes coarse features to halos and groups those at the same place', () => {
    const { pins, halos, layer } = split();
    layer.setFeatures([feat('a', 'exact'), feat('b', 'city'), feat('c', 'city'), feat('d', 'country', 51, 10)]);
    expect([...pins.features.keys()]).toEqual(['a']);
    expect(halos.count()).toBe(2);
    const berlin = [...halos.features.values()].find((f) => f.props['grouped'] === 2);
    expect(berlin?.name).toBe('b');
    expect(layer.count()).toBe(4);
  });

  it('moves a feature between pins and halos when its precision changes', () => {
    const { pins, halos, layer } = split();
    layer.setFeatures([feat('a', 'city'), feat('b', 'city')]);
    layer.upsert(feat('a', 'exact'));
    expect(pins.features.has('a')).toBe(true);
    expect([...halos.features.values()].map((f) => f.props['grouped'])).toEqual([undefined]);
    layer.remove('b');
    expect(halos.count()).toBe(0);
    layer.upsert(feat('a', 'region'));
    expect(pins.count()).toBe(0);
    expect(halos.count()).toBe(1);
    expect(layer.count()).toBe(1);
  });
});
