#!/bin/bash
# Copyright (c) 2026 Nrupal Akolkar
# SPDX-License-Identifier: Apache-2.0
#
# Guardian Mesh reproducible build script (release-pipeline tooling, not product runtime).
#
# Builds the daemon release binary TWICE from separate clean copies with
# SOURCE_DATE_EPOCH and GUARDIAN_MESH_GIT_COMMIT set, then compares the
# SHA-256 hashes. Exit 0 only if hashes are identical.

set -euo pipefail

SOURCE_DIR="$(cd "${1:-.}" && pwd)"

echo "=== Guardian Mesh Reproducible Build Verification ==="
echo "Source directory: $SOURCE_DIR"
echo

# Get commit time and hash
cd "$SOURCE_DIR"
COMMIT_TIME=$(git log -1 --format=%ct)
COMMIT_HASH=$(git rev-parse HEAD)
echo "Commit: $COMMIT_HASH"
echo "Commit time (SOURCE_DATE_EPOCH): $COMMIT_TIME"
echo

# Create two temporary build directories
TMPDIR1=$(mktemp -d)
TMPDIR2=$(mktemp -d)

trap "rm -rf '$TMPDIR1' '$TMPDIR2'" EXIT

echo "=== Build 1: $TMPDIR1 ==="
cp -r "$SOURCE_DIR/." "$TMPDIR1/"
cd "$TMPDIR1"

export SOURCE_DATE_EPOCH="$COMMIT_TIME"
export GUARDIAN_MESH_GIT_COMMIT="$COMMIT_HASH"
export LC_ALL=C
export TZ=UTC

RUSTFLAGS="--remap-path-prefix $TMPDIR1=/guardian-mesh" cargo build --release --locked

BINARY1="$TMPDIR1/target/release/guardian-meshd"
HASH1=$(sha256sum "$BINARY1" | awk '{print $1}')
echo "Build 1 SHA-256: $HASH1"
echo

echo "=== Build 2: $TMPDIR2 ==="
cp -r "$SOURCE_DIR/." "$TMPDIR2/"
cd "$TMPDIR2"

export SOURCE_DATE_EPOCH="$COMMIT_TIME"
export GUARDIAN_MESH_GIT_COMMIT="$COMMIT_HASH"
export LC_ALL=C
export TZ=UTC

RUSTFLAGS="--remap-path-prefix $TMPDIR2=/guardian-mesh" cargo build --release --locked

BINARY2="$TMPDIR2/target/release/guardian-meshd"
HASH2=$(sha256sum "$BINARY2" | awk '{print $1}')
echo "Build 2 SHA-256: $HASH2"
echo

echo "=== Verification ==="
if [ "$HASH1" = "$HASH2" ]; then
  echo "✓ REPRODUCIBLE: Both builds produced identical binaries"
  echo "  SHA-256: $HASH1"
  exit 0
else
  echo "✗ NOT REPRODUCIBLE: Build outputs differ"
  echo "  Build 1: $HASH1"
  echo "  Build 2: $HASH2"
  exit 1
fi
