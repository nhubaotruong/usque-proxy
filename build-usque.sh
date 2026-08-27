#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/usque-bind"

echo "Building usque AAR via gomobile..."
# Force Go 1.26.3 toolchain to match go.mod and avoid gvisor build tag conflicts
export GOTOOLCHAIN=go1.26.3
# Ensure GOPATH/bin is in PATH for gomobile/gobind
export PATH="$(go env GOPATH)/bin:$PATH"
# Use Go module proxy to avoid fetching from deleted repos (e.g. mitchellh/osext)
export GOPROXY=https://proxy.golang.org,direct
# -ldflags="-s -w" strips debug info for smaller binary
# CGO flags: 16KB page alignment (Android 15+ devices use 16KB pages; larger alignment is compatible with 4KB-page devices):
#   -z,max-page-size / common-page-size = 16KB page alignment for PT_LOAD segments
#   --gc-sections removes unreferenced code/data (paired with -ffunction/data-sections)
#   -O1 enables linker optimization pass; --as-needed skips unused shared libs
export CGO_CFLAGS="-O2 -ffunction-sections -fdata-sections"
export CGO_LDFLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 -Wl,--gc-sections -Wl,-O1 -Wl,--as-needed"
PGO_FLAG=""
if [ -f default.pgo ]; then
  echo "Using PGO profile: default.pgo"
  PGO_FLAG="-pgo=default.pgo"
fi

# -androidapi 30 = AAR minSdk (Android 11+); matches app/build.gradle.kts minSdk
gomobile bind -v -target=android/arm64,android/amd64 -androidapi 30 \
  -trimpath \
  -ldflags="-s -w" \
  ${PGO_FLAG:+"$PGO_FLAG"} \
  -o ../app/libs/usquebind.aar .

echo "Done: app/libs/usquebind.aar"
