import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
/// <reference types="vitest/config" />
import { defineConfig } from 'vitest/config';
import { viteStaticCopy } from 'vite-plugin-static-copy';

// Cesium ships workers/assets/widgets that must be served as static files.
// They are copied to /cesium/ and CESIUM_BASE_URL is set in index.html before Cesium loads.
// vite-plugin-static-copy v4 keeps the source path (node_modules/cesium/Build/Cesium/Workers/...), so the four
// leading segments are stripped: without that every worker, texture and the imagery 404 to index.html.
const cesiumSource = 'node_modules/cesium/Build/Cesium';
const cesiumBaseUrl = 'cesium';

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    viteStaticCopy({
      targets: ['Workers', 'ThirdParty', 'Assets', 'Widgets'].map((dir) => ({
        src: `${cesiumSource}/${dir}`,
        dest: cesiumBaseUrl,
        rename: { stripBase: cesiumSource.split('/').length },
      })),
    }),
  ],
  define: { CESIUM_BASE_URL: JSON.stringify(`/${cesiumBaseUrl}/`) },
  // satellite.js v7 ships an optional WASM/pthreads worker build that uses top-level await;
  // ESM worker output supports it (the default IIFE format does not). We only use the pure-JS API.
  worker: { format: 'es' },
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://localhost:8000', changeOrigin: true, ws: true } },
  },
  build: { chunkSizeWarningLimit: 6000, sourcemap: false },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
});
