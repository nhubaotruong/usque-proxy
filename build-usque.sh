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
# CGO_LDFLAGS: -Wl,-z,max-page-size=16384 ensures 16KB page alignment
#   required for Android 15+ (API 35) 16KB page size support
export CGO_LDFLAGS="-Wl,-z,max-page-size=16384"
PGO_FLAG=""
if [ -f default.pgo ]; then
  echo "Using PGO profile: default.pgo"
  PGO_FLAG="-pgo=default.pgo"
fi

gomobile bind -v -target=android/arm64,android/amd64 -androidapi 31 \
  -trimpath \
  -ldflags="-s -w" \
  ${PGO_FLAG:+"$PGO_FLAG"} \
  -o ../app/libs/usquebind.aar .

echo "Done: app/libs/usquebind.aar"
