# WebUI — Guardian Mesh Control Plane

A **React + TypeScript + Vite** progressive web app (PWA) that provides the
management console for Guardian Mesh: 2FA login, status dashboards, and APK
packaging via Capacitor.

## Stack

- **React 19** + **react-router-dom** for the UI
- **Vite 8** for build/dev (fast, ESM-native)
- **vite-plugin-pwa** for offline/progressive-web-app support
- **@capacitor/* 8** for building the native **Android APK**
- **@protobuf-ts/grpcweb-transport** for talking to the daemon over gRPC-web
- **qrcode.react** for 2FA / QR flows

## Commands

| Command | What it does |
|---------|--------------|
| `npm ci` | Install locked dependencies |
| `npm run dev` | Local dev server with HMR |
| `npm run build` | Type-check + production bundle → `dist/` |
| `npm run lint` | ESLint gate (CI enforces this) |
| `npm run preview` | Preview the production build |
| `npx cap add android` | Generate the Android platform (once) |
| `npx cap sync` | Copy `dist/` + plugins into the Android project |
| `npx cap open android` | Open the Android project in Android Studio |

## Android APK build

```bash
npm ci
npm run build          # produces dist/ (the web asset bundle)
npx cap add android    # only needed the first time
npx cap sync           # copies dist/ into the native project
cd android && ./gradlew assembleDebug
# APK → android/app/build/outputs/apk/debug/app-debug.apk
```

> **Troubleshooting:** `android/` is gitignored because it is generated. If
> `npx cap add android` fails with "android platform already exists" but the
> folder is empty, delete `android/` and run it again.

## Configuration

- `vite.config.ts` sets the GitHub Pages base path to `/guardian-mesh/` and
  configures the PWA manifest + Workbox precaching.
- `capacitor.config.json` defines `appId` (`com.guardianmesh.app`), `appName`,
  and `webDir: dist`.

## CI

The `webui-ci.yml` GitHub Action runs `npm ci`, `npm run build`, and
`npm run lint`, then uploads the PWA artifact and deploys to GitHub Pages.
The `android-apk.yml` Action builds and uploads the debug APK.

> The 2FA flow lives in `src/lib/auth.tsx`. The lint rule in
> `eslint.config.js` allows underscore-prefixed unused arguments (e.g.
> `_totpCode`) so the auth API contract stays stable while lint stays clean.

## See also

- `../README.md` — whole-project overview.
- `../guardian-meshd/README.md` — the daemon this UI talks to.