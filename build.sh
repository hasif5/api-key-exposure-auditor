#!/usr/bin/env bash
# Build a store-ready zip (Chrome Web Store / Edge Add-ons) — runtime files only.
# Usage:  ./build.sh
set -euo pipefail

out="dist"
name="api-key-exposure-auditor-store.zip"
mkdir -p "$out"
rm -f "$out/$name"

zip -rq "$out/$name" \
  manifest.json background.js content lib popup dashboard collection icons \
  -x '*/.*'

echo "Built $out/$name"
echo "Upload this file in the Chrome Web Store / Edge Add-ons developer dashboard."
