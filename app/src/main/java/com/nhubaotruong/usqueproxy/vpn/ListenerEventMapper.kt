package com.nhubaotruong.usqueproxy.vpn

/**
 * Maps Go tunnel listener callbacks to typed [VpnServiceEvent]s.
 * Pure logic — no Android dependencies, unit-testable.
 */
object ListenerEventMapper {
    private var lastError: String? = null

    fun mapState(state: String): VpnServiceEvent? = when (state) {
        "connecting" -> VpnServiceEvent.Connecting
        "connected" -> {
            // A fresh connect cycle resets the error dedup, mirroring the old
            // watchdog's `lastSurfacedError = ""` on reconnect.
            lastError = null
            VpnServiceEvent.Started
        }
        "disconnected" -> VpnServiceEvent.Disconnecting
        "stopped" -> VpnServiceEvent.Stopped
        else -> null
    }

    /**
     * Surfaces each distinct error once: returns null when [err] equals the last
     * mapped error message, restoring the old service's `lastSurfacedError` gate.
     */
    fun mapError(err: String): VpnServiceEvent.Error? {
        if (err == lastError) return null
        lastError = err
        return VpnServiceEvent.Error(err)
    }
}
