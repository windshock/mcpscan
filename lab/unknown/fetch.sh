#!/usr/bin/env bash
# Download the four "unknown-lab" packages: Flowise 3.1.0/3.0.13 (npm) and
# Upsonic 0.72.0/0.71.6 (PyPI). Each is extracted into ./sources/<name>-<ver>/.
#
# This corpus is a blind-test for MCP scanners — the lab framework does NOT
# pre-label expected_findings. We measure what each scanner detects on real
# released code.

set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$LAB_DIR/sources"
mkdir -p "$SRC_DIR"

NPM_PACKAGES=(
  "flowise@3.1.0"
  "flowise@3.0.13"
)

PIP_PACKAGES=(
  "upsonic==0.72.0"
  "upsonic==0.71.6"
)

fetch_npm() {
  local spec="$1"
  local name="${spec%@*}"
  local ver="${spec#*@}"
  local target="$SRC_DIR/${name}-${ver}"
  if [[ -d "$target" ]]; then
    echo "[skip] $target already extracted"
    return
  fi
  echo "[npm] $spec → $target"
  local tarball
  tarball="$(npm view "$spec" dist.tarball)"
  mkdir -p "$target"
  curl -fsSL "$tarball" | tar -xz -C "$target" --strip-components=1
}

fetch_pip() {
  local spec="$1"
  local name="${spec%==*}"
  local ver="${spec#*==}"
  local target="$SRC_DIR/${name}-${ver}"
  if [[ -d "$target" ]]; then
    echo "[skip] $target already extracted"
    return
  fi
  echo "[pip] $spec → $target"
  # PyPI JSON API: pull the sdist URL directly (pip download forces a build,
  # which we don't want for source-only inspection).
  local sdist_url
  sdist_url="$(curl -fsSL "https://pypi.org/pypi/${name}/${ver}/json" |
    python3 -c '
import json, sys
data = json.load(sys.stdin)
for url in data.get("urls", []):
    if url.get("packagetype") == "sdist":
        print(url["url"])
        break')"
  if [[ -z "$sdist_url" ]]; then
    echo "[warn] no sdist for $spec — falling back to wheel"
    sdist_url="$(curl -fsSL "https://pypi.org/pypi/${name}/${ver}/json" |
      python3 -c '
import json, sys
for url in json.load(sys.stdin).get("urls", []):
    if url.get("packagetype") == "bdist_wheel":
        print(url["url"]); break')"
  fi
  local tmp
  tmp="$(mktemp -d)"
  local fname="${sdist_url##*/}"
  curl -fsSL "$sdist_url" -o "$tmp/$fname"
  mkdir -p "$target"
  case "$fname" in
    *.tar.gz) tar -xz -f "$tmp/$fname" -C "$target" --strip-components=1 ;;
    *.whl)    (cd "$target" && unzip -q "$tmp/$fname") ;;
    *)        echo "[err] unknown archive type: $fname"; exit 1 ;;
  esac
  rm -rf "$tmp"
}

for spec in "${NPM_PACKAGES[@]}"; do
  fetch_npm "$spec"
done

for spec in "${PIP_PACKAGES[@]}"; do
  fetch_pip "$spec"
done

echo ""
echo "Fetched packages:"
ls -1 "$SRC_DIR"
