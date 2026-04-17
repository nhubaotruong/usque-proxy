#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/usque-bind"

echo "Building usque AAR via gomobile..."
# Force Go 1.24.2 toolchain to match go.mod and avoid gvisor build tag conflicts
export GOTOOLCHAIN=go1.24.2
# Ensure GOPATH/bin is in PATH for gomobile/gobind
export PATH="$(go env GOPATH)/bin:$PATH"
# Use Go module proxy to avoid fetching from deleted repos (e.g. mitchellh/osext)
export GOPROXY=https://proxy.golang.org,direct
# -ldflags="-s -w" strips debug info for smaller binary
# CGO flags tuned for Android 15+ (API 35) 16KB page size:
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

gomobile bind -v -target=android/arm64 -androidapi 35 \
  -trimpath \
  -ldflags="-s -w" \
  ${PGO_FLAG:+"$PGO_FLAG"} \
  -o ../app/libs/usquebind.aar .

echo "Done: app/libs/usquebind.aar"
