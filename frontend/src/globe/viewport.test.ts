import { describe, expect, it } from 'vitest';

import { tiledInRange, viewportBboxes } from './viewport';

describe('viewport', () => {
  it('widens the view to whole hundredths of a degree', () => {
    expect(viewportBboxes(13.3012, 52.4049, 13.5071, 52.6001)).toEqual(['13.30,52.40,13.51,52.61']);
  });

  it('splits a view that crosses the antimeridian', () => {
    expect(viewportBboxes(179.5, -17, -179.5, -16)).toEqual(['179.50,-17.00,180.00,-16.00', '-180.00,-17.00,-179.50,-16.00']);
  });

  it('only fetches tiled layers when zoomed in', () => {
    expect(tiledInRange(null)).toBe(false);
    expect(tiledInRange({ bboxes: [], height: 5_000_000 })).toBe(false);
    expect(tiledInRange({ bboxes: [], height: 50_000 })).toBe(true);
  });
});
