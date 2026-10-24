// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

// Drift guard: ensures the release log (releases.ts) stays current with the
// CHANGELOG. Reads both files, extracts version lists, and exits non-zero if
// they differ in content or order. This makes "release log updated with each
// release" a build failure when forgotten, not a hope.

import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Read CHANGELOG.md and extract version headers (## [x.y.z] - date)
function extractChangelogVersions() {
  const changelogPath = join(__dirname, '..', '..', 'CHANGELOG.md')
  const content = readFileSync(changelogPath, 'utf-8')
  const versionRegex = /^## \[(\d+\.\d+\.\d+)\]/gm
  const versions = []
  let match
  while ((match = versionRegex.exec(content)) !== null) {
    versions.push(match[1])
  }
  return versions
}

// Read releases.ts and extract version entries (version: "x.y.z")
function extractReleasesVersions() {
  const releasesPath = join(__dirname, '..', 'src', 'data', 'releases.ts')
  const content = readFileSync(releasesPath, 'utf-8')
  const versionRegex = /version:\s*["'](\d+\.\d+\.\d+)["']/g
  const versions = []
  let match
  while ((match = versionRegex.exec(content)) !== null) {
    versions.push(match[1])
  }
  return versions
}

// Main
const changelogVersions = extractChangelogVersions()
const releasesVersions = extractReleasesVersions()

console.log(`CHANGELOG versions (${changelogVersions.length}): ${changelogVersions.join(', ')}`)
console.log(`releases.ts versions (${releasesVersions.length}): ${releasesVersions.join(', ')}`)

// Check if lists match in content and order
if (changelogVersions.length !== releasesVersions.length) {
  console.error(`\n❌ DRIFT DETECTED: Version count mismatch.`)
  console.error(`   CHANGELOG has ${changelogVersions.length} versions, releases.ts has ${releasesVersions.length}.`)
  process.exit(1)
}

for (let i = 0; i < changelogVersions.length; i++) {
  if (changelogVersions[i] !== releasesVersions[i]) {
    console.error(`\n❌ DRIFT DETECTED: Version mismatch at position ${i}.`)
    console.error(`   CHANGELOG: ${changelogVersions[i]}`)
    console.error(`   releases.ts: ${releasesVersions[i]}`)
    console.error(`\nThe release log (webui/src/data/releases.ts) must be updated to match CHANGELOG.md.`)
    process.exit(1)
  }
}

console.log(`✅ Release log is current: all ${changelogVersions.length} versions match in content and order.`)
