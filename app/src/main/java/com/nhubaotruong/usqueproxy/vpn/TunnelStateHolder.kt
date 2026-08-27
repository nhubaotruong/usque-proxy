package com.nhubaotruong.usqueproxy.vpn

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/** Process-wide tunnel state, replacing the service companion statics. */
object TunnelStateHolder {
    @Volatile
    var isRunning: Boolean = false

    @Volatile
    var lastError: String? = null

    private val _events = MutableSharedFlow<VpnServiceEvent>(replay = 1, extraBufferCapacity = 16)
    val events: SharedFlow<VpnServiceEvent> = _events.asSharedFlow()

    fun emit(event: VpnServiceEvent) {
        _events.tryEmit(event)
    }

    fun clearError() {
        lastError = null
    }
}
