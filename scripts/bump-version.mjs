#!/usr/bin/env node
// bump-version.mjs - STANDARD app versioning (author-time bump).
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const ver = process.argv[2];
if (!ver || !/^\d+\.\d+\.\d+$/.test(ver)) {
  console.error("usage: node scripts/bump-version.mjs <X.Y.Z>");
  process.exit(1);
}
const log = [];

// 1) webui/package.json - the single source of truth
const pkg = JSON.parse(readFileSync("webui/package.json", "utf8"));
const prev = pkg.version;
pkg.version = ver;
writeFileSync("webui/package.json", JSON.stringify(pkg, null, 2) + "\n");
log.push(`webui/package.json  ${prev} -> ${ver}`);

// 2) on-page <meta name="app-version"> marker (web app)
const meta = "webui/index.html";
if (existsSync(meta)) {
  const src = readFileSync(meta, "utf8");
  const out = src.replace(/(<meta name="app-version" content=")\d+\.\d+\.\d+(")/g, `$1${ver}$2`);
  writeFileSync(meta, out);
  log.push(`webui/index.html app-version meta  ${out !== src ? "updated" : "NO MATCH"}`);
}

// 4b) vite-plugin-pwa manifest version (built into the app at build time)
const vcfg = "webui/vite.config.ts";
if (existsSync(vcfg)) {
  const src = readFileSync(vcfg, "utf8");
  const out = src.replace(/(version:\s*")[^"]*(")/, `$1${ver}$2`);
  writeFileSync(vcfg, out);
  log.push(`webui/vite.config.ts manifest version -> ${ver}  ${out !== src ? "" : "(NO MATCH)"}`);
}

// 6) CHANGELOG heading - promote Unreleased into a dated release section
const cl = "CHANGELOG.md";
if (existsSync(cl)) {
  const today = new Date().toISOString().slice(0, 10);
  const src = readFileSync(cl, "utf8");
  if (src.includes("## [Unreleased]")) {
    const out = src.replace("## [Unreleased]", `## [Unreleased]\n\n## [${ver}] - ${today}`);
    writeFileSync(cl, out);
    log.push(`CHANGELOG.md  new heading [${ver}] - ${today}`);
  }
}


console.log("bumped to " + ver + ":");
for (const line of log) console.log("  " + line);
console.log(`next: git commit -am "chore: v${ver}" && git tag v${ver} && git push --follow-tags`);
