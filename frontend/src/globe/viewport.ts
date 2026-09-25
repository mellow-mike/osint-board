import * as Cesium from 'cesium';

export interface Viewport {
  /** `minLon,minLat,maxLon,maxLat` in degrees; two boxes when the view crosses the antimeridian. */
  bboxes: string[];
  /** camera height above the ellipsoid, metres */
  height: number;
}

/** Tiled layers (cell towers, Wi-Fi) are fetched for the view only below this camera height (about zoom 10). */
export const TILED_MAX_HEIGHT_M = 200_000;

const down = (v: number) => (Math.floor(v * 100) / 100).toFixed(2);
const up = (v: number) => (Math.ceil(v * 100) / 100).toFixed(2);

/** Bounding boxes for a view rectangle in degrees, widened to 0.01° so small camera moves reuse cached queries. */
export function viewportBboxes(west: number, south: number, east: number, north: number): string[] {
  if (west <= east) return [`${down(west)},${down(south)},${up(east)},${up(north)}`];
  return [`${down(west)},${down(south)},180.00,${up(north)}`, `-180.00,${down(south)},${up(east)},${up(north)}`];
}

export function readViewport(viewer: Cesium.Viewer): Viewport | null {
  const rect = viewer.camera.computeViewRectangle(viewer.scene.globe.ellipsoid);
  if (!rect) return null; // looking past the globe
  const deg = Cesium.Math.toDegrees;
  return {
    bboxes: viewportBboxes(deg(rect.west), deg(rect.south), deg(rect.east), deg(rect.north)),
    height: viewer.camera.positionCartographic.height,
  };
}

export function tiledInRange(viewport: Viewport | null): viewport is Viewport {
  return viewport !== null && viewport.height <= TILED_MAX_HEIGHT_M;
}
