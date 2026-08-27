package com.nhubaotruong.usqueproxy

import com.nhubaotruong.usqueproxy.data.ProfileType
import com.nhubaotruong.usqueproxy.data.VpnPrefs
import com.nhubaotruong.usqueproxy.vpn.TunnelConfigBuilder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelConfigBuilderTest {
    private val baseConfig = """{"private_key":"pk","id":"abc","access_token":"tok","endpoint_v4":"1.2.3.4","ipv4":"10.0.0.2"}"""

    @Test
    fun mergesPrefsOverridesIntoActiveConfig() {
        val prefs = VpnPrefs().copy(
            warpConfigJson = baseConfig,
            activeProfile = ProfileType.WARP,
            customSni = "custom.example.com",
            useHttp2 = true,
        )
        val json = JSONObject(
            TunnelConfigBuilder.build(
                prefs,
                systemDns = listOf("1.1.1.1", "9.9.9.9"),
                privateDnsActive = true,
                networkType = "wifi",
            )
        )
        assertEquals("custom.example.com", json.getString("sni"))
        assertEquals(true, json.getBoolean("use_http2"))
        assertEquals(true, json.getBoolean("private_dns_active"))
        assertEquals("1.1.1.1", json.getJSONArray("system_dns").getString(0))
        assertEquals("9.9.9.9", json.getJSONArray("system_dns").getString(1))
        assertEquals("wifi", json.getString("network_type"))
        assertEquals("pk", json.getString("private_key"))
    }

    @Test
    fun throwsWhenNoActiveConfig() {
        val prefs = VpnPrefs()
        try {
            TunnelConfigBuilder.build(prefs)
            assertTrue("expected IllegalArgumentException", false)
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }
}
