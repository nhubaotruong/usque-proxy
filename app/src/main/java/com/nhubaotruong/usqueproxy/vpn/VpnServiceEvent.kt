package com.nhubaotruong.usqueproxy.vpn

/** Typed events from the VPN service to the UI, emitted via [TunnelStateHolder.events]. */
sealed interface VpnServiceEvent {
    data object Connecting : VpnServiceEvent
    data object Started : VpnServiceEvent
    data object Disconnecting : VpnServiceEvent
    data object Stopped : VpnServiceEvent
    data class Error(val message: String) : VpnServiceEvent
    data class Stats(val stats: TunnelStats) : VpnServiceEvent
}
