# Usque Proxy — Tunnel Reliability Overhaul

## What This Is

An Android VPN app (usque-proxy) that tunnels traffic through Cloudflare's MASQUE protocol using QUIC + Connect-IP. The app suffers from silent connection death after 2-4 hours — it reports "connected" but traffic stops flowing. The goal is to surgically add CloseError-based reconnection from usque-android to the stable v1.27 codebase, keeping all existing mechanisms intact.

## Core Value

VPN tunnel connections must stay reliably alive for hours/days without silent death — if the connection breaks, detect it immediately and reconnect.

## Current Milestone: v1.1 Surgical CloseError Port

**Goal:** Revert to v1.27 baseline, then port only CloseError-based reconnection and constant retry delay from usque-android

**Target features:**
- Revert all Go and Kotlin code to v1.27 state
- Port CloseError detection in forwardUp/forwardDown (fatal vs non-fatal error classification)
- Port constant reconnect delay (replace exponential backoff with 1s constant delay)

## Requirements

### Validated

- ✓ QUIC + MASQUE tunnel establishment — existing
- ✓ Android VPN service with TUN device — existing
- ✓ DNS resolution (DoH/DoQ/System) — existing
- ✓ Network change detection (WiFi ↔ cellular) — existing
- ✓ Android Doze mode handling (battery exemption, alarm keepalive) — existing
- ✓ Dual-stack Happy Eyeballs connection racing — existing
- ✓ Self-signed certificate generation and caching — existing
- ✓ Split tunneling and DNS configuration — existing
- ✓ Debug/stats UI for tunnel diagnostics — existing

### Active

- [x] Revert all Go and Kotlin code to v1.27 baseline — Phase 1
- [ ] Port CloseError detection in forwardUp/forwardDown from usque-android
- [ ] Port constant 1s reconnect delay (replace exponential backoff)

### Out of Scope

- v1.0 Phase 2/3 work (complexity removal, compatibility verification) — deferred; taking minimal approach first
- New features or UI changes — reliability-focused
- DNS subsystem changes — works fine as-is
- Keepalive/watchdog/rotation removal — keeping v1.27's existing mechanisms
- usque-rs (Rust library) changes

## Context

**v1.0 lesson learned:** Phase 1 made too many changes at once (Keepalive rework, DNS fast path, waitForNetwork rewrite, fd dup, adaptive keepalive removal, etc.). The minimal approach is better: start from the known-good v1.27, add only the two patterns that directly address the root cause.

**The root cause:** After 2-4 hours, the MASQUE session expires server-side while the QUIC transport stays alive. The app shows "connected" but no IP traffic flows.

**The fix (from usque-android):** Forwarding goroutines detect `connectip.CloseError` on read/write and trigger immediate reconnection. Non-fatal errors are logged but don't trigger reconnect. Constant 1s retry delay instead of exponential backoff.

**Reference:** `usque-android/api/tunnel.go` — `MaintainTunnel()` function

**Key files to modify:**
- `usque-bind/bind.go` — forwardUp/forwardDown error classification, reconnect delay
- `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt` — revert to v1.27

## Constraints

- **Tech stack**: Go (gomobile) + Kotlin, Android VPN service — no changes
- **Protocol**: QUIC + MASQUE Connect-IP via quic-go and connect-ip-go libraries
- **Compatibility**: Must maintain existing JNI interface (`Usquebind.startTunnel`, `getStats`, etc.)
- **Android**: Keep all v1.27 Doze handling, battery exemption, network callbacks, watchdog as-is

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Revert to v1.27 instead of building on v1.38 | v1.0 Phase 1 changed too much at once; v1.27 is the stable baseline | v1.1 |
| Port only CloseError + constant retry | Minimal surgical changes that address root cause without disrupting working mechanisms | v1.1 |
| Keep v1.27's keepalive/watchdog/rotation | These may be redundant with CloseError detection, but removing them is a separate concern | v1.1 |
| Defer complexity removal (v1.0 Phase 2/3) | Get the fix working first, then decide what to simplify | v1.1 |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-01 — Phase 1 complete (v1.27 revert)*
