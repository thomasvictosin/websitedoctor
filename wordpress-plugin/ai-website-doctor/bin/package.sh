#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "$0")/.." && pwd)"
output_dir="${1:-$plugin_dir/dist}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

version="$(sed -n 's/^[[:space:]]*\* Version: \([0-9][0-9.]*\).*/\1/p' "$plugin_dir/ai-website-doctor.php" | head -n 1)"
if [[ ! "$version" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]]; then
  echo "Could not read a valid plugin version from the plugin header." >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/ai-website-doctor"
cp "$plugin_dir/ai-website-doctor.php" "$plugin_dir/readme.txt" "$work_dir/ai-website-doctor/"
mkdir -p "$work_dir/ai-website-doctor/bin"
cp "$plugin_dir/bin/staging-conflict-check.php" "$work_dir/ai-website-doctor/bin/"
(
  cd "$work_dir"
  zip -qr "$output_dir/ai-website-doctor-$version.zip" ai-website-doctor
)
echo "Created $output_dir/ai-website-doctor-$version.zip"
