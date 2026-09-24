import * as Cesium from 'cesium';

import { assertTrueScale } from './scaling';

/**
 * Creates a Cesium viewer that needs no Cesium ion account:
 *  - imagery: VITE_TILE_URL template if provided (e.g. a self-hosted tile server or OSM with attribution),
 *    otherwise the Natural Earth II imagery bundled with Cesium (fully offline);
 *  - terrain: the WGS84 ellipsoid (swap in a self-hosted terrain provider when available);
 *  - geocoder disabled (it would call ion) — our own search does that job.
 */
export async function createViewer(container: HTMLElement): Promise<Cesium.Viewer> {
  Cesium.Ion.defaultAccessToken = '';

  const viewer = new Cesium.Viewer(container, {
    baseLayer: Cesium.ImageryLayer.fromProviderAsync(pickImagery()),
    terrainProvider: new Cesium.EllipsoidTerrainProvider(),
    geocoder: false,
    baseLayerPicker: false,
    sceneModePicker: false,
    navigationHelpButton: false,
    homeButton: true,
    infoBox: false,
    selectionIndicator: false,
    fullscreenButton: false,
    animation: true,
    timeline: true,
    shouldAnimate: true,
    requestRenderMode: false,
  });

  const scene = viewer.scene;
  assertTrueScale(scene);
  scene.globe.enableLighting = true;
  scene.globe.showGroundAtmosphere = true;
  if (scene.skyAtmosphere) scene.skyAtmosphere.show = true;
  scene.globe.depthTestAgainstTerrain = false;
  scene.screenSpaceCameraController.minimumZoomDistance = 50;
  scene.screenSpaceCameraController.maximumZoomDistance = 60_000_000;
  viewer.clock.clockRange = Cesium.ClockRange.UNBOUNDED;
  viewer.clock.multiplier = 1;

  viewer.camera.setView({
    destination: Cesium.Cartesian3.fromDegrees(10, 25, 22_000_000),
  });
  return viewer;
}

async function pickImagery(): Promise<Cesium.ImageryProvider> {
  const tileUrl = import.meta.env.VITE_TILE_URL;
  if (tileUrl) {
    return new Cesium.UrlTemplateImageryProvider({
      url: `${tileUrl.replace(/\/$/, '')}/{z}/{x}/{y}.png`,
      credit: import.meta.env.VITE_TILE_ATTRIBUTION ?? '',
      maximumLevel: 19,
    });
  }
  return Cesium.TileMapServiceImageryProvider.fromUrl(Cesium.buildModuleUrl('Assets/Textures/NaturalEarthII'));
}
