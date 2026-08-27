package com.nhubaotruong.usqueproxy.vpn

import org.json.JSONObject

data class TunnelStats(
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
    val connected: Boolean = false,
    val running: Boolean = false,
    val uptimeSec: Long = 0,
    val hasNetwork: Boolean = true,
    val connectCount: Long = 0,
    val lastError: String? = null,
)

/** Parses the Go `getStats()` JSON. Unknown/missing fields default safely. */
fun parseTunnelStats(json: String): TunnelStats {
    val o = JSONObject(json)
    return TunnelStats(
        txBytes = o.optLong("tx_bytes", 0L),
        rxBytes = o.optLong("rx_bytes", 0L),
        connected = o.optBoolean("connected", false),
        running = o.optBoolean("running", false),
        uptimeSec = o.optLong("uptime_sec", 0L),
        hasNetwork = o.optBoolean("has_network", true),
        connectCount = o.optLong("connect_count", 0L),
        lastError = o.optString("last_error", "").ifEmpty { null },
    )
}
