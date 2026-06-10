#!/usr/bin/env bash
# Quick installer (macOS / Linux) for the API Key Exposure Auditor.
# Downloads the latest source into a folder, then tells you how to load it.
# Usage:  curl -fsSL https://raw.githubusercontent.com/hasif5/google-api-key-exposure-auditor/main/install.sh | bash
#   or:   ./install.sh
set -euo pipefail

repo="hasif5/google-api-key-exposure-auditor"
dest="$HOME/google-api-key-exposure-auditor"
tmp="$(mktemp -d)"

echo "Downloading latest source..."
curl -fsSL "https://github.com/$repo/archive/refs/heads/main.zip" -o "$tmp/src.zip"
unzip -q "$tmp/src.zip" -d "$tmp"

rm -rf "$dest"
mv "$tmp/google-api-key-exposure-auditor-main" "$dest"
rm -rf "$tmp"

cat <<EOF

Installed to: $dest

Now load it in your browser (one time):
  1. Open  chrome://extensions   (or  edge://extensions )
  2. Turn on  Developer mode  (top-right toggle)
  3. Click  Load unpacked  and select:
       $dest

To update later, just run this installer again.
EOF
