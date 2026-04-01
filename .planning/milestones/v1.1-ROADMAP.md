# Roadmap: Usque Proxy — Surgical CloseError Port

## Overview

Revert all Go and Kotlin source files to the stable v1.27 baseline, then surgically port only two patterns from usque-android: CloseError-based reconnection in the forwarding loops and constant 1-second reconnect delay. This is the minimal change set that addresses the root cause of silent tunnel death.

## Milestones

- <details><summary>v1.0 Tunnel Reliability Overhaul (Phases 1-3) -- SUPERSEDED</summary>Replaced by v1.1 minimal approach after Phase 1 changed too much at once.</details>
- **v1.1 Surgical CloseError Port** - Phases 1-2 (in progress)

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Revert to v1.27 Baseline** - Restore all Go and Kotlin source files to their v1.27 state (completed 2026-04-01)
- [x] **Phase 2: Surgical CloseError Port** - Add CloseError detection in forwarding loops and constant reconnect delay (completed 2026-04-01)

## Phase Details

### Phase 1: Revert to v1.27 Baseline
**Goal**: The codebase is back to the known-stable v1.27 state, undoing all v1.0/v1.38 changes
**Depends on**: Nothing (first phase)
**Requirements**: REV-01, REV-02
**Success Criteria** (what must be TRUE):
  1. All Go source files in usque-bind/ are byte-identical to their v1.27 tag state
  2. All Kotlin source files are byte-identical to their v1.27 tag state
  3. The app builds successfully and the AAR can be produced from the reverted Go code
**Plans**: 1 plan (complete)

### Phase 2: Surgical CloseError Port
**Goal**: Forwarding loops detect MASQUE session death via CloseError and trigger immediate reconnection with constant delay
**Depends on**: Phase 1
**Requirements**: CERR-01, CERR-02, CERR-03, CERR-04, RDLY-01
**Success Criteria** (what must be TRUE):
  1. When the MASQUE session expires server-side, forwardUp and forwardDown detect the CloseError and trigger reconnection within seconds
  2. Non-CloseError packet errors (transient read/write failures) are logged but do not cause reconnection
  3. After tunnel death, reconnection retries use a constant 1-second delay instead of exponential backoff
  4. The app builds, produces a valid AAR, and the tunnel can be started on-device
**Plans:** 2/2 plans complete

Plans:
- [x] 02-01-PLAN.md — Add CloseError classification to forwardUp and forwardDown
- [x] 02-02-PLAN.md — Replace backoff with constant delay, fix QUIC config, cleanup dead code, build AAR

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Revert to v1.27 Baseline | 1/1 | Complete    | 2026-04-01 |
| 2. Surgical CloseError Port | 1/2 | Complete    | 2026-04-01 |
