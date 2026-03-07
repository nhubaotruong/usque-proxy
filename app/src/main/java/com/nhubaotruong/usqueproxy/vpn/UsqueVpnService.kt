package com.nhubaotruong.usqueproxy.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.R
import com.nhubaotruong.usqueproxy.data.Office365Endpoints
import com.nhubaotruong.usqueproxy.data.DnsMode
import com.nhubaotruong.usqueproxy.data.ProfileType
import com.nhubaotruong.usqueproxy.data.SplitMode
import com.nhubaotruong.usqueproxy.data.VpnPreferences
import com.nhubaotruong.usqueproxy.data.VpnPrefs
import com.nhubaotruong.usqueproxy.tile.VpnTileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import usquebind.Usquebind
import usquebind.VpnProtector

class UsqueVpnService : VpnService() {

    companion object {
        const val TAG = "UsqueVpnService"
        const val ACTION_STOP = "com.nhubaotruong.usqueproxy.STOP_VPN"
        const val CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 1

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var lastError: String? = null
            private set

        fun clearError() { lastError = null }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelThread: Thread? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var startJob: kotlinx.coroutines.Job? = null
    @Volatile
    private var currentNetwork: Network? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification())

        startJob = CoroutineScope(Dispatchers.IO).launch {
            val prefs = VpnPreferences(this@UsqueVpnService).prefsFlow.first()

            if (!prefs.isActiveRegistered || prefs.activeConfigJson.isEmpty()) {
                Log.e(TAG, "No config found for active profile, stopping")
                stopSelf()
                return@launch
            }

            // Refresh Office 365 endpoint cache before starting VPN
            if (prefs.bypassOffice365) {
                runCatching { Office365Endpoints.refreshCache(this@UsqueVpnService) }
            }

            startVpn(prefs)
        }
        return START_STICKY
    }

    private fun startVpn(prefs: VpnPrefs) {
        val config = JSONObject(prefs.activeConfigJson)
        // SNI: use custom if set, otherwise default to ZT SNI for ZeroTrust profile
        if (prefs.customSni.isNotBlank()) {
            config.put("sni", prefs.customSni)
        } else if (prefs.activeProfile == ProfileType.ZERO_TRUST) {
            config.put("sni", "zt-masque.cloudflareclient.com")
        }
        if (prefs.connectUri.isNotBlank()) config.put("connect_uri", prefs.connectUri)

        val builder = Builder()
            .setMtu(1280)
            .setSession("UsqueProxy")
            .setMetered(prefs.isMetered)

        // Addresses from config
        config.optString("ipv4", "").takeIf { it.isNotEmpty() }?.let {
            builder.addAddress(it, 32)
        }
        config.optString("ipv6", "").takeIf { it.isNotEmpty() }?.let {
            builder.addAddress(it, 128)
        }

        // DNS
        when (prefs.dnsMode) {
            DnsMode.SYSTEM -> {
                val dns = getSystemDnsServers()
                Log.d(TAG, "Using system DNS: $dns")
                dns.forEach { builder.addDnsServer(it) }
                if (prefs.preventDnsLeak) {
                    config.put("prevent_dns_leak", true)
                    config.put("dns_servers", JSONArray(dns))
                }
            }
            DnsMode.CLOUDFLARE -> {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("2606:4700:4700::1111")
                if (prefs.preventDnsLeak) {
                    config.put("prevent_dns_leak", true)
                    config.put("doh_url", "https://cloudflare-dns.com/dns-query")
                }
            }
            DnsMode.CUSTOM_DOH -> {
                builder.addDnsServer("10.255.255.53")
                builder.addRoute("10.255.255.53", 32)
                config.put("doh_url", prefs.dohUrl)
                if (prefs.preventDnsLeak) {
                    config.put("prevent_dns_leak", true)
                }
            }
        }

        val configJson = config.toString()

        // Route exclusions (local network bypass + Office 365 bypass)
        val needsExcludeRoute = prefs.bypassLocalNetwork || prefs.bypassOffice365
        if (needsExcludeRoute && Build.VERSION.SDK_INT >= 33) {
            // Must add catch-all routes first, then exclude
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)

            if (prefs.bypassLocalNetwork) {
                // IPv4 private/reserved
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("10.0.0.0"), 8))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("169.254.0.0"), 16))  // DHCP Unspecified
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("172.16.0.0"), 12))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("192.0.0.0"), 24))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("192.168.0.0"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("224.0.0.0"), 24))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("240.0.0.0"), 4))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("255.255.255.255"), 32))  // DHCP Broadcast
                // IPv6 private/local
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("fd00::"), 8))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("fe80::"), 10))       // Link Local
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("ff01::"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("ff02::"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("ff03::"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("ff04::"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("ff05::"), 16))
                // 127.0.0.0/8 not needed — loopback is never routed through VPN
            }

            if (prefs.bypassOffice365) {
                val o365Ips = Office365Endpoints.getIpRanges(this)
                Log.d(TAG, "Excluding ${o365Ips.size} Office 365 IP ranges from VPN")
                for (cidr in o365Ips) {
                    runCatching {
                        val parts = cidr.split("/")
                        val addr = java.net.InetAddress.getByName(parts[0])
                        val prefix = parts[1].toInt()
                        builder.excludeRoute(android.net.IpPrefix(addr, prefix))
                    }.onFailure { e ->
                        Log.w(TAG, "Failed to exclude O365 route $cidr: ${e.message}")
                    }
                }
            }
        } else if (prefs.bypassLocalNetwork) {
            // API < 33 with local bypass: use additive public routes
            addPublicRoutes(builder)
        } else {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }

        // Split tunneling
        when (prefs.splitMode) {
            SplitMode.INCLUDE -> {
                for (pkg in prefs.includedApps) {
                    runCatching { builder.addAllowedApplication(pkg) }
                }
            }
            SplitMode.EXCLUDE -> {
                for (pkg in prefs.excludedApps) {
                    runCatching { builder.addDisallowedApplication(pkg) }
                }
                runCatching { builder.addDisallowedApplication(packageName) }
            }
            SplitMode.ALL -> {
                runCatching { builder.addDisallowedApplication(packageName) }
            }
        }

        // Set underlying network so Android routes the VPN's own traffic
        // (including the Go tunnel's QUIC connection) through the real network,
        // not back through the TUN — avoids DNS black-hole during connect.
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val underlying = cm.activeNetwork
        if (underlying != null) {
            builder.setUnderlyingNetworks(arrayOf(underlying))
        }

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }

        val fd = vpnInterface!!.fd
        isRunning = true
        VpnTileService.requestUpdate(this)

        val protector = object : VpnProtector {
            override fun protectFd(fd: Long): Boolean {
                return protect(fd.toInt())
            }
        }

        tunnelThread = Thread({
            try {
                Usquebind.startTunnel(configJson, fd.toLong(), protector)
            } catch (e: Throwable) {
                Log.e(TAG, "Tunnel error", e)
                lastError = e.message ?: "Tunnel failed"
            } finally {
                // Mark not running and request service stop on main thread.
                // Don't call stopVpn() here — it joins this thread and does
                // heavy cleanup; let onDestroy handle it instead.
                isRunning = false
                VpnTileService.requestUpdate(this@UsqueVpnService)
                android.os.Handler(android.os.Looper.getMainLooper()).post { stopSelf() }
            }
        }, "usque-tunnel").also { it.start() }

        registerNetworkCallback()
    }

    /**
     * Listens for network changes (WiFi ↔ cellular, network loss/gain).
     * When the underlying network changes, the QUIC tunnel's UDP socket becomes
     * stale — we stop the Go tunnel so its reconnect loop re-establishes on
     * the new network.
     */
    /**
     * Tracks the system default network via [ConnectivityManager.registerDefaultNetworkCallback].
     * Unlike [ConnectivityManager.registerNetworkCallback] with a request filter, this fires
     * reliably whenever the OS switches the default network (WiFi ↔ cellular), including
     * when the app is in the background, because the VPN runs as a foreground service.
     */
    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        currentNetwork = cm.activeNetwork
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val previous = currentNetwork
                currentNetwork = network
                if (network != previous && isRunning) {
                    Log.i(TAG, "Default network changed: $previous -> $network, restarting tunnel")
                    setUnderlyingNetworks(arrayOf(network))
                    restartTunnel()
                }
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Default network lost: $network")
                if (currentNetwork == network) {
                    currentNetwork = null
                    if (isRunning) setUnderlyingNetworks(null)
                }
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (network == currentNetwork && isRunning &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    setUnderlyingNetworks(arrayOf(network))
                }
            }
        }
        cm.registerDefaultNetworkCallback(callback)
        networkCallback = callback
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            runCatching { cm.unregisterNetworkCallback(it) }
            networkCallback = null
            currentNetwork = null
        }
    }

    private fun restartTunnel() {
        // Signal Go to tear down the current QUIC connection and reconnect.
        // Unlike stopTunnel(), this keeps the reconnect loop alive.
        Usquebind.reconnect()
    }

    private fun stopVpn() {
        startJob?.cancel()
        startJob = null
        unregisterNetworkCallback()
        Usquebind.stopTunnel()       // Cancel Go context
        tunnelThread?.join(5000)     // Wait for Go to finish using the fd
        tunnelThread = null
        vpnInterface?.close()        // Safe — Go is done
        vpnInterface = null
        isRunning = false
        VpnTileService.requestUpdate(this)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun getSystemDnsServers(): List<String> = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return listOf("1.1.1.1")
        val lp = cm.getLinkProperties(network) ?: return listOf("1.1.1.1")
        val servers = lp.dnsServers.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
        servers.ifEmpty { listOf("1.1.1.1") }
    } catch (e: SecurityException) {
        Log.w(TAG, "Cannot read system DNS, falling back to 1.1.1.1", e)
        listOf("1.1.1.1")
    }

    private fun addPublicRoutes(builder: Builder) {
        // IPv4 public ranges
        // Skip: 10/8, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.168/16,
        //        224.0.0/24, 240/4, 255.255.255.255/32

        // 0-9
        builder.addRoute("0.0.0.0", 5)        // 0-7
        builder.addRoute("8.0.0.0", 7)        // 8-9
        // skip 10.0.0.0/8
        builder.addRoute("11.0.0.0", 8)       // 11
        builder.addRoute("12.0.0.0", 6)       // 12-15
        builder.addRoute("16.0.0.0", 4)       // 16-31
        builder.addRoute("32.0.0.0", 3)       // 32-63
        builder.addRoute("64.0.0.0", 3)       // 64-95
        builder.addRoute("96.0.0.0", 4)       // 96-111
        builder.addRoute("112.0.0.0", 5)      // 112-119
        builder.addRoute("120.0.0.0", 6)      // 120-123
        builder.addRoute("124.0.0.0", 7)      // 124-125
        builder.addRoute("126.0.0.0", 8)      // 126
        // skip 127.0.0.0/8
        builder.addRoute("128.0.0.0", 3)      // 128-159
        builder.addRoute("160.0.0.0", 5)      // 160-167
        builder.addRoute("168.0.0.0", 8)      // 168
        // 169.x minus 169.254.0.0/16
        builder.addRoute("169.0.0.0", 9)      // 169.0-127
        builder.addRoute("169.128.0.0", 10)   // 169.128-191
        builder.addRoute("169.192.0.0", 11)   // 169.192-223
        builder.addRoute("169.224.0.0", 12)   // 169.224-239
        builder.addRoute("169.240.0.0", 13)   // 169.240-247
        builder.addRoute("169.248.0.0", 14)   // 169.248-251
        builder.addRoute("169.252.0.0", 15)   // 169.252-253
        // skip 169.254.0.0/16
        builder.addRoute("169.255.0.0", 16)   // 169.255
        builder.addRoute("170.0.0.0", 7)      // 170-171
        // 172.x minus 172.16.0.0/12
        builder.addRoute("172.0.0.0", 12)     // 172.0-15
        // skip 172.16.0.0/12 (172.16-31)
        builder.addRoute("172.32.0.0", 11)    // 172.32-63
        builder.addRoute("172.64.0.0", 10)    // 172.64-127
        builder.addRoute("172.128.0.0", 9)    // 172.128-255
        for (i in 173..191) builder.addRoute("$i.0.0.0", 8)
        // 192.x minus 192.0.0.0/24 and 192.168.0.0/16
        // skip 192.0.0.0/24
        builder.addRoute("192.0.1.0", 24)     // 192.0.1
        builder.addRoute("192.0.2.0", 23)     // 192.0.2-3
        builder.addRoute("192.0.4.0", 22)     // 192.0.4-7
        builder.addRoute("192.0.8.0", 21)     // 192.0.8-15
        builder.addRoute("192.0.16.0", 20)    // 192.0.16-31
        builder.addRoute("192.0.32.0", 19)    // 192.0.32-63
        builder.addRoute("192.0.64.0", 18)    // 192.0.64-127
        builder.addRoute("192.0.128.0", 17)   // 192.0.128-255
        builder.addRoute("192.1.0.0", 16)     // 192.1
        builder.addRoute("192.2.0.0", 15)     // 192.2-3
        builder.addRoute("192.4.0.0", 14)     // 192.4-7
        builder.addRoute("192.8.0.0", 13)     // 192.8-15
        builder.addRoute("192.16.0.0", 12)    // 192.16-31
        builder.addRoute("192.32.0.0", 11)    // 192.32-63
        builder.addRoute("192.64.0.0", 10)    // 192.64-127
        builder.addRoute("192.128.0.0", 11)   // 192.128-159
        builder.addRoute("192.160.0.0", 13)   // 192.160-167
        // skip 192.168.0.0/16
        builder.addRoute("192.169.0.0", 16)   // 192.169
        builder.addRoute("192.170.0.0", 15)   // 192.170-171
        builder.addRoute("192.172.0.0", 14)   // 192.172-175
        builder.addRoute("192.176.0.0", 12)   // 192.176-191
        builder.addRoute("192.192.0.0", 10)   // 192.192-255
        for (i in 193..223) builder.addRoute("$i.0.0.0", 8)
        // 224.x minus 224.0.0.0/24
        builder.addRoute("224.0.1.0", 24)     // 224.0.1
        builder.addRoute("224.0.2.0", 23)     // 224.0.2-3
        builder.addRoute("224.0.4.0", 22)     // 224.0.4-7
        builder.addRoute("224.0.8.0", 21)     // 224.0.8-15
        builder.addRoute("224.0.16.0", 20)    // 224.0.16-31
        builder.addRoute("224.0.32.0", 19)    // 224.0.32-63
        builder.addRoute("224.0.64.0", 18)    // 224.0.64-127
        builder.addRoute("224.0.128.0", 17)   // 224.0.128-255
        builder.addRoute("224.1.0.0", 16)     // 224.1
        builder.addRoute("224.2.0.0", 15)     // 224.2-3
        builder.addRoute("224.4.0.0", 14)     // 224.4-7
        builder.addRoute("224.8.0.0", 13)     // 224.8-15
        builder.addRoute("224.16.0.0", 12)    // 224.16-31
        builder.addRoute("224.32.0.0", 11)    // 224.32-63
        builder.addRoute("224.64.0.0", 10)    // 224.64-127
        builder.addRoute("224.128.0.0", 9)    // 224.128-255
        for (i in 225..239) builder.addRoute("$i.0.0.0", 8)
        // skip 240.0.0.0/4 (includes 255.255.255.255/32)

        // IPv6 public ranges
        // Skip: fd00::/8, fe80::/10, ff01::/16, ff02::/16, ff03::/16, ff04::/16, ff05::/16
        builder.addRoute("::", 1)              // 0000::-7fff::
        builder.addRoute("8000::", 2)          // 8000::-bfff::
        builder.addRoute("c000::", 3)          // c000::-dfff::
        builder.addRoute("e000::", 4)          // e000::-efff::
        builder.addRoute("f000::", 5)          // f000::-f7ff::
        builder.addRoute("f800::", 6)          // f800::-fbff::
        builder.addRoute("fc00::", 8)          // fc00::/8
        // skip fd00::/8
        builder.addRoute("fe00::", 9)          // fe00::-fe7f::
        // skip fe80::/10 (link local)
        builder.addRoute("fec0::", 10)         // fec0::-feff::
        builder.addRoute("ff00::", 16)         // ff00::/16
        // skip ff01::-ff05::/16
        builder.addRoute("ff06::", 15)         // ff06-ff07
        builder.addRoute("ff08::", 13)         // ff08-ff0f
        builder.addRoute("ff10::", 12)         // ff10-ff1f
        builder.addRoute("ff20::", 11)         // ff20-ff3f
        builder.addRoute("ff40::", 10)         // ff40-ff7f
        builder.addRoute("ff80::", 9)          // ff80-ffff
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, "VPN Service", NotificationManager.IMPORTANCE_LOW
        ).apply { description = "UsqueProxy VPN status" }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val stopIntent = Intent(this, UsqueVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = Intent(this, MainActivity::class.java)
        val openPending = PendingIntent.getActivity(
            this, 0, openIntent, PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("UsqueProxy")
            .setContentText("VPN is active")
            .setSmallIcon(R.drawable.ic_vpn_tile)
            .setContentIntent(openPending)
            .addAction(Notification.Action.Builder(null, "Disconnect", stopPending).build())
            .setOngoing(true)
            .build()
    }
}
