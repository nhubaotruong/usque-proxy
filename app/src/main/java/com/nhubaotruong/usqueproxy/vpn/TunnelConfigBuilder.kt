package com.nhubaotruong.usqueproxy.vpn

import com.nhubaotruong.usqueproxy.data.DnsMode
import com.nhubaotruong.usqueproxy.data.ProfileType
import com.nhubaotruong.usqueproxy.data.VpnPrefs
import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds the tunnel config JSON passed to `Usquebind.startTunnel`.
 * Pure function — no Android dependencies, unit-testable.
 *
 * The dynamic fields (private DNS state, system DNS servers, network type) are
 * resolved by the service from the underlying network's LinkProperties and
 * passed in; the JSON keys and shapes match what `startVpn` produced before
 * this extraction.
 */
object TunnelConfigBuilder {
    fun build(
        prefs: VpnPrefs,
        privateDnsActive: Boolean = false,
        systemDns: List<String> = emptyList(),
        networkType: String = "",
    ): String {
        val active = prefs.activeConfigJson
        require(active.isNotEmpty()) { "no active config" }
        val o = JSONObject(active)
        // SNI: use custom if set, otherwise default to ZT SNI for ZeroTrust profile
        if (prefs.customSni.isNotBlank()) {
            o.put("sni", prefs.customSni)
        } else if (prefs.activeProfile == ProfileType.ZERO_TRUST) {
            o.put("sni", "zt-masque.cloudflareclient.com")
        }
        if (prefs.connectUri.isNotBlank()) o.put("connect_uri", prefs.connectUri)
        if (prefs.useHttp2) o.put("use_http2", true)
        if (privateDnsActive) o.put("private_dns_active", true)
        when (prefs.dnsMode) {
            DnsMode.SYSTEM -> o.put("system_dns", JSONArray(systemDns))
            DnsMode.CLOUDFLARE -> Unit
            DnsMode.CUSTOM_DOH -> o.put("doh_url", prefs.dohUrl)
            DnsMode.CUSTOM_DOQ -> o.put("doq_url", prefs.doqUrl)
        }
        o.put("network_type", networkType)
        return o.toString()
    }
}
