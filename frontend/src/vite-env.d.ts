/// <reference types="vite/client" />

declare const CESIUM_BASE_URL: string;

interface ImportMetaEnv {
  /** Tile template base, e.g. https://tile.openstreetmap.org/ — omit to use the bundled offline Natural Earth II imagery. */
  readonly VITE_TILE_URL?: string;
  readonly VITE_TILE_ATTRIBUTION?: string;
  /** API origin when not served behind the same host (dev uses the Vite proxy). */
  readonly VITE_API_BASE?: string;
}
