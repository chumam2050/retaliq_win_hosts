#!/usr/bin/env bash
set -euo pipefail

# Simple POSIX shell script to publish the RetaliqHosts project for multiple RIDs
# Produces outputs directly into build/win-x64 and build/win-x86

PROJ_PATH="RetaliqHosts.csproj"
OUT_ROOT="build"
RIDS=("win-x64" "win-x86")
CONFIG="Release"
SELF_CONTAINED="true"

usage() {
  cat <<EOF
Usage: $0 [project-path] [out-root]

Defaults:
  project-path: ${PROJ_PATH}
  out-root: ${OUT_ROOT}

This script runs 'dotnet publish' for ${RIDS[*]} and places outputs under <out-root>/<rid>.
EOF
}

if [[ "${1-}" == "-h" || "${1-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ${1-} != "" ]]; then
  PROJ_PATH="$1"
fi

if [[ ${2-} != "" ]]; then
  OUT_ROOT="$2"
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet CLI not found in PATH" >&2
  exit 2
fi

echo "Project: $PROJ_PATH"
echo "Output root: $OUT_ROOT"
echo "Configuration: $CONFIG"
echo "Self-contained: $SELF_CONTAINED"

for rid in "${RIDS[@]}"; do
  outdir="$OUT_ROOT/$rid"
  echo "Publishing for $rid -> $outdir"
  mkdir -p "$outdir"
  dotnet publish "$PROJ_PATH" -c "$CONFIG" -r "$rid" --self-contained "$SELF_CONTAINED" -o "$outdir"
  echo "Published $rid -> $outdir"
done

echo "All done."
