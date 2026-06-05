/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    // jsdom gives our React tree a window/document; the alternative
    // (happy-dom) is faster but has gaps that bite real UI tests.
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // Don't collect tests from production bundles or node_modules.
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
