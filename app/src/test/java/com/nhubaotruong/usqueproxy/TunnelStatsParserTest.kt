package com.nhubaotruong.usqueproxy

import com.nhubaotruong.usqueproxy.vpn.parseTunnelStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TunnelStatsParserTest {
    @Test
    fun parsesFullStatsJson() {
        val s = parseTunnelStats(
            """{"running":true,"connected":true,"tx_bytes":1234,"rx_bytes":5678,"uptime_sec":3600,"has_network":true,"connect_count":2}"""
        )
        assertEquals(1234L, s.txBytes)
        assertEquals(5678L, s.rxBytes)
        assertEquals(true, s.connected)
        assertEquals(3600L, s.uptimeSec)
        assertEquals(2L, s.connectCount)
        assertNull(s.lastError)
    }

    @Test
    fun defaultsMissingFieldsSafely() {
        val s = parseTunnelStats("""{"running":false}""")
        assertEquals(0L, s.txBytes)
        assertEquals(false, s.connected)
        assertNull(s.lastError)
    }

    @Test
    fun parsesLastErrorWhenPresent() {
        val s = parseTunnelStats("""{"running":true,"connected":false,"last_error":"dial failed"}""")
        assertEquals("dial failed", s.lastError)
    }
}
