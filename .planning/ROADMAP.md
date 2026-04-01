# Roadmap: Usque Proxy — Tunnel Reliability Overhaul

## Overview

Replace usque-proxy's fragile multi-layer tunnel monitoring with usque-android's proven dual-goroutine forwarding pattern. Phase 1 ports the new tunnel core with CloseError-based reconnection. Phase 2 strips out all the old complexity that the new pattern makes obsolete. Phase 3 verifies that the Android integration surface (JNI, stats, Doze, network callbacks) still works correctly with the simplified tunnel layer.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Tunnel Core Port** - Port usque-android's forwarding loop and reconnect pattern into usque-proxy
- [ ] **Phase 2: Complexity Removal** - Strip out all obsolete monitoring, keepalive, and rotation mechanisms
- [ ] **Phase 3: Compatibility Verification** - Confirm JNI interface, stats, network callbacks, and Doze handling work with the new tunnel core

## Phase Details

### Phase 1: Tunnel Core Port
**Goal**: Tunnel connections detect death immediately through forwarding loop errors and reconnect within seconds
**Depends on**: Nothing (first phase)
**Requirements**: TUNL-01, TUNL-02, TUNL-03, TUNL-04, TUNL-05, CMPT-05
**Success Criteria** (what must be TRUE):
  1. When the MASQUE session dies server-side, the app detects the failure and begins reconnecting within seconds (not minutes)
  2. After a tunnel death, the app reconnects with a constant 1-second delay and retries indefinitely until successful
  3. Each reconnect cycle starts clean with no leaked connections, transports, or goroutines from the previous attempt
  4. Individual packet read/write errors on the TUN device do not cause unnecessary reconnections
**Plans:** 2 plans

Plans:
- [x] 01-01-PLAN.md — Rewrite forwarding loops with CloseError classification and simplify reconnect to constant 1s delay
- [ ] 01-02-PLAN.md — Remove obsolete stats fields, dead code (nextBackoff, livenessCheck), and clean up Kotlin side

### Phase 2: Complexity Removal
**Goal**: All obsolete monitoring and keepalive mechanisms are removed, leaving only the forwarding-loop-based detection
**Depends on**: Phase 1
**Requirements**: RMVL-01, RMVL-02, RMVL-03, RMVL-04, RMVL-05, RMVL-06, RMVL-07, RMVL-08, RMVL-09
**Success Criteria** (what must be TRUE):
  1. No Go-side liveness goroutine, delivery ratio tracking, or forced rotation exists in the codebase
  2. No Android-side keepalive scheduling (ScheduledExecutor, AlarmManager, debounce) exists in the codebase
  3. No watchdog stall detection or consecutiveKeepaliveFailures logic exists in the codebase
  4. The tunnel still detects death and reconnects correctly after all removals (Phase 1 behavior preserved)
**Plans**: TBD

Plans:
- [ ] 02-01: TBD
- [ ] 02-02: TBD

### Phase 3: Compatibility Verification
**Goal**: The simplified tunnel integrates correctly with all existing Android-side functionality
**Depends on**: Phase 2
**Requirements**: CMPT-01, CMPT-02, CMPT-03, CMPT-04
**Success Criteria** (what must be TRUE):
  1. `Usquebind.startTunnel`, `stopTunnel`, `reconnect`, and `getStats` JNI calls work without crashes or errors
  2. The stats UI displays current connection status and rx/tx byte counts accurately
  3. Switching between WiFi and cellular triggers a reconnect and traffic resumes on the new network
  4. Screen off/on and Doze idle mode transitions do not break the tunnel or prevent reconnection
**Plans**: TBD

Plans:
- [ ] 03-01: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Tunnel Core Port | 0/2 | Not started | - |
| 2. Complexity Removal | 0/2 | Not started | - |
| 3. Compatibility Verification | 0/1 | Not started | - |
