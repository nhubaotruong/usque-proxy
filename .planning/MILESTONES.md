# Milestones

## v1.1 Surgical CloseError Port (Shipped: 2026-04-01)

**Phases completed:** 2 phases, 3 plans, 3 tasks

**Key accomplishments:**

- CloseError-based error classification in forwardUp/forwardDown: fatal session-death errors trigger reconnect, transient errors are logged and skipped
- Constant 1s reconnect delay, fixed QUIC config matching usque-android, unconditional DNS reset, and removal of 86 lines of dead adaptive/backoff code

---
