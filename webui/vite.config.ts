// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import { VitePWA } from "vite-plugin-pwa"

export default defineConfig({
  base: "/guardian-mesh/",
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
        start_url: "/guardian-mesh/",
        icons: [
          { src: "/guardian-mesh/icons/icon-192x192.png", sizes: "192x192", type: "image/png" },
          { src: "/guardian-mesh/icons/icon-512x512.png", sizes: "512x512", type: "image/png" },
          { src: "/guardian-mesh/icons/icon-512x512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
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
