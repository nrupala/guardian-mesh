// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import { VitePWA } from "vite-plugin-pwa"

// Base path: "/guardian-mesh/" for the GitHub Pages build;
// the guardian.aimlds.org build sets VITE_BASE_PATH=/ (domain root).
const basePath = process.env.VITE_BASE_PATH ?? "/guardian-mesh/"

export default defineConfig({
  base: basePath,
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      includeAssets: ["favicon.svg"],
      manifest: {
        name: "Guardian Mesh",
        short_name: "GuardianMesh",
        description: "Secure gRPC mesh daemon control panel",
        theme_color: "#0f172a",
        background_color: "#0f172a",
        display: "standalone",
        orientation: "portrait",
        start_url: basePath,
        icons: [
          { src: `${basePath}icons/icon-192x192.png`, sizes: "192x192", type: "image/png" },
          { src: `${basePath}icons/icon-512x512.png`, sizes: "512x512", type: "image/png" },
          { src: `${basePath}icons/icon-512x512.png`, sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,svg,png,ico,json}"],
        // The codetopo topology snapshot is a download for agents, not an
        // app asset — keep it out of the offline precache.
        globIgnores: ["**/guardian-mesh-topology.json"],
      },
    }),
  ],
})
