import { allowsPin, precisionOf } from './HaloLayer';
import type { LayerRenderer, RenderFeature } from './types';

/**
 * Wraps a point renderer so a `points`/`heat`/`tracks` layer never draws a pin for anything coarser than street
 * precision: those features go to a halo renderer instead (docs/05-globe.md, "Precision and halos").
 *
 * Coarse placements pile up on the same spot (every country-level GDELT event sits on the country centroid),
 * so features sharing a precision and a position share one halo; its props carry `grouped` = how many.
 */
export class PrecisionSplitLayer implements LayerRenderer {
  readonly layerId: string;
  private readonly groupOf = new Map<string, string>(); // coarse feature id -> halo key
  private readonly groups = new Map<string, Map<string, RenderFeature>>();

  constructor(
    private readonly pins: LayerRenderer,
    private readonly halos: LayerRenderer,
  ) {
    this.layerId = pins.layerId;
  }

  setFeatures(features: RenderFeature[]): void {
    this.groupOf.clear();
    this.groups.clear();
    const fine: RenderFeature[] = [];
    for (const f of features) {
      if (allowsPin(f.props)) fine.push(f);
      else this.addCoarse(f);
    }
    this.pins.setFeatures(fine);
    this.halos.setFeatures([...this.groups.keys()].map((k) => this.haloFor(k)).filter((f): f is RenderFeature => f !== null));
  }

  upsert(f: RenderFeature): void {
    this.removeCoarse(f.id);
    if (allowsPin(f.props)) {
      this.pins.upsert(f);
      return;
    }
    this.pins.remove(f.id);
    const key = this.addCoarse(f);
    const halo = this.haloFor(key);
    if (halo) this.halos.upsert(halo);
  }

  remove(id: string): void {
    this.pins.remove(id);
    this.removeCoarse(id);
  }

  setVisible(visible: boolean): void {
    this.pins.setVisible(visible);
    this.halos.setVisible(visible);
  }

  count(): number {
    return this.pins.count() + this.groupOf.size;
  }

  destroy(): void {
    this.pins.destroy();
    this.halos.destroy();
  }

  private addCoarse(f: RenderFeature): string {
    const key = `${this.layerId}:${precisionOf(f.props)}:${f.lat.toFixed(4)},${f.lon.toFixed(4)}`;
    let members = this.groups.get(key);
    if (!members) {
      members = new Map();
      this.groups.set(key, members);
    }
    members.set(f.id, f);
    this.groupOf.set(f.id, key);
    return key;
  }

  private removeCoarse(id: string): void {
    const key = this.groupOf.get(id);
    if (key === undefined) return;
    this.groupOf.delete(id);
    const members = this.groups.get(key);
    members?.delete(id);
    if (!members || members.size === 0) {
      this.groups.delete(key);
      this.halos.remove(key);
      return;
    }
    const halo = this.haloFor(key);
    if (halo) this.halos.upsert(halo);
  }

  private haloFor(key: string): RenderFeature | null {
    const members = this.groups.get(key);
    const first = members?.values().next().value;
    if (!members || !first) return null;
    const n = members.size;
    return {
      ...first,
      id: key,
      name: first.name,
      props: n > 1 ? { ...first.props, grouped: n } : first.props,
    };
  }
}
