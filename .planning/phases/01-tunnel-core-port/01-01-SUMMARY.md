---
phase: 01-tunnel-core-port
plan: 01
subsystem: tunnel
tags: [go, quic, masque, connect-ip, error-handling, reconnect]

# Dependency graph
requires: []
provides:
  - CloseError-based error classification in forwarding loops
  - Constant 1s reconnect delay replacing exponential backoff
  - 30s QUIC keepalive period
  - Simplified maintainTunnel without lifetime rotation or livenessCheck spawn
affects: [01-02-PLAN]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "CloseError classification: fatal errors (connectip.CloseError) trigger reconnect, transient errors log+continue"
    - "Constant reconnect delay instead of exponential backoff"
    - "Network-triggered reconnect uses 200ms stabilization delay"

key-files:
  created: []
  modified:
    - usque-bind/bind.go

key-decisions:
  - "Keep nextBackoff function definition for Plan 02 cleanup"
  - "Keep livenessCheck function definition for Plan 02 cleanup"
  - "ICMP device.WritePacket errors use CloseError classification (non-fatal continue) matching usque-android reference"

patterns-established:
  - "CloseError check pattern: errors.As(err, new(*connectip.CloseError)) before sending to errChan"
  - "TUN device errors always fatal, Connect-IP errors classified by CloseError"

requirements-completed: [TUNL-01, TUNL-02, TUNL-03, TUNL-04, TUNL-05, CMPT-05]

# Metrics
duration: 3min
completed: 2026-04-01
---

# Phase 01 Plan 01: Tunnel Core Port Summary

**CloseError-based error classification in forwarding loops with constant 1s reconnect delay replacing exponential backoff**

## Performance

- **Duration:** 3 min
- **Started:** 2026-04-01T07:41:02Z
- **Completed:** 2026-04-01T07:44:07Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- forwardUp and forwardDown now classify errors: CloseError triggers reconnect, transient Connect-IP errors log and continue, TUN device errors always trigger reconnect
- maintainTunnel uses constant 1s reconnect delay everywhere, removing exponential backoff (1s-60s range)
- Removed lifetime rotation timer (maxConnLifetime 2h), livenessCheck goroutine spawn, connCtx/connCancel, networkGraceAttempts
- QUIC keepalive period changed from 25s to 30s matching usque-android

## Task Commits

Each task was committed atomically:

1. **Task 1: Rewrite forwardUp and forwardDown with CloseError classification** - `00af300` (feat)
2. **Task 2: Simplify maintainTunnel reconnect loop** - `bf28f44` (feat)

## Files Created/Modified
- `usque-bind/bind.go` - Rewritten forwardUp, forwardDown error handling and maintainTunnel reconnect logic

## Decisions Made
- Kept nextBackoff function definition (unused now) for Plan 02 cleanup to avoid removing code that Plan 02 explicitly handles
- Kept livenessCheck function definition for Plan 02 cleanup
- ICMP device.WritePacket gets CloseError classification (matching usque-android where ICMP write errors are non-fatal unless connection closed)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Pre-existing gvisor dependency build failure (gvisor runtime_constants_go126.go conflicts with Go version) prevents `go build` from succeeding - this affects unmodified code as well and is not caused by these changes. Syntax validation via `gofmt -e` confirms no syntax errors in our changes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Plan 01-02 can now proceed to remove livenessCheck function, nextBackoff function, delivery ratio monitoring, and related dead code
- The forwarding loops and reconnect logic match usque-android's proven pattern

## Self-Check: PASSED

- FOUND: usque-bind/bind.go
- FOUND: 01-01-SUMMARY.md
- FOUND: commit 00af300
- FOUND: commit bf28f44

---
*Phase: 01-tunnel-core-port*
*Completed: 2026-04-01*
