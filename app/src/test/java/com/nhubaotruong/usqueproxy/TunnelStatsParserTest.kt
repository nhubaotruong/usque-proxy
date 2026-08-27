package com.nhubaotruong.usqueproxy

import com.nhubaotruong.usqueproxy.vpn.parseTunnelStats
import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelStatsParserTest {
    @Test
    fun parsesFullStatsJson() {
        val s =
            parseTunnelStats(
                """{"running":true,"connected":true,"tx_bytes":1234,"rx_bytes":5678,"uptime_sec":3600}""",
            )
        assertEquals(1234L, s.txBytes)
        assertEquals(5678L, s.rxBytes)
        assertEquals(true, s.connected)
        assertEquals(true, s.running)
        assertEquals(3600L, s.uptimeSec)
    }

    @Test
    fun defaultsMissingFieldsSafely() {
        val s = parseTunnelStats("""{"running":false}""")
        assertEquals(0L, s.txBytes)
        assertEquals(false, s.connected)
        assertEquals(0L, s.uptimeSec)
    }
}
