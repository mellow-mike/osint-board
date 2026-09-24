import * as Cesium from 'cesium';

/**
 * Scale is never faked: the globe is Cesium's WGS84 ellipsoid (a = 6 378 137 m, 1/f = 298.257223563),
 * heights are metres above that ellipsoid and vertical exaggeration is pinned to 1.
 */
export const WGS84 = {
  a: 6378137.0,
  f: 1 / 298.257223563,
  b: 6356752.314245,
} as const;

export function assertTrueScale(scene: Cesium.Scene): void {
  const radii = scene.globe.ellipsoid.radii;
  if (Math.abs(radii.x - WGS84.a) > 1e-3 || Math.abs(radii.z - WGS84.b) > 1e-3) {
    throw new Error('Globe ellipsoid is not WGS84');
  }
  scene.verticalExaggeration = 1.0;
  scene.verticalExaggerationRelativeHeight = 0.0;
}

/** Approximate ground metres per screen pixel at the camera's nadir (good enough for a scale readout). */
export function metersPerPixel(scene: Cesium.Scene): number | null {
  const camera = scene.camera;
  const frustum = camera.frustum;
  if (!(frustum instanceof Cesium.PerspectiveFrustum) || frustum.fovy === undefined) return null;
  const height = camera.positionCartographic.height;
  const canvasHeight = scene.drawingBufferHeight || 1;
  return (2 * height * Math.tan(frustum.fovy / 2)) / canvasHeight;
}

/** Height above the ellipsoid for a feature in a given altitude mode. */
export function featureHeight(altitude: 'clamp' | 'absolute', alt: number | null | undefined): number {
  if (altitude === 'clamp') return 0;
  return alt ?? 0;
}
