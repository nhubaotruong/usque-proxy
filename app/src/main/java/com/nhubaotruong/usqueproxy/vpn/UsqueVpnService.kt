package com.nhubaotruong.usqueproxy.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
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

        // Pre-computed IpPrefix exclusions — avoids InetAddress.getByName() on every VPN start
        private val LOCAL_NETWORK_EXCLUSIONS_V4: List<Pair<java.net.InetAddress, Int>> by lazy {
            listOf(
                "10.0.0.0" to 8,
                "169.254.0.0" to 16,       // Link-local
                "172.16.0.0" to 12,
                "192.0.0.0" to 24,
                "192.168.0.0" to 16,
                "224.0.0.0" to 24,          // Local multicast
                "240.0.0.0" to 4,           // Reserved
                "255.255.255.255" to 32,    // Broadcast
            ).map { (addr, prefix) -> java.net.InetAddress.getByName(addr) to prefix }
        }

        private val LOCAL_NETWORK_EXCLUSIONS_V6: List<Pair<java.net.InetAddress, Int>> by lazy {
            listOf(
                "fd00::" to 8,              // ULA
                "fe80::" to 10,             // Link-local
                "ff01::" to 16,             // Interface-local multicast
                "ff02::" to 16,             // Link-local multicast
                "ff03::" to 16,             // Realm-local multicast
                "ff04::" to 16,             // Admin-local multicast
                "ff05::" to 16,             // Site-local multicast
            ).map { (addr, prefix) -> java.net.InetAddress.getByName(addr) to prefix }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelThread: Thread? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var startJob: kotlinx.coroutines.Job? = null
    @Volatile
    private var currentNetwork: Network? = null
    @Volatile
    private var underlyingNetworkSet = false

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
                Log.d(TAG, "Using system DNS (bypass tunnel): $dns")
                dns.forEach { addr ->
                    builder.addDnsServer(addr)
                    // Exclude DNS server IPs from VPN routes so DNS (port 53)
                    // and DNS-over-TLS (port 853) traffic bypasses the tunnel.
                    runCatching {
                        val inet = java.net.InetAddress.getByName(addr)
                        val prefix = if (inet is java.net.Inet6Address) 128 else 32
                        builder.excludeRoute(IpPrefix(inet, prefix))
                    }.onFailure { e ->
                        Log.w(TAG, "Failed to exclude DNS route $addr: ${e.message}")
                    }
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

        // Routes: catch-all + exclusions
        builder.addRoute("0.0.0.0", 0)
        builder.addRoute("::", 0)

        if (prefs.bypassLocalNetwork) {
            // IPv4 private/reserved
            for ((addr, prefix) in LOCAL_NETWORK_EXCLUSIONS_V4) {
                builder.excludeRoute(android.net.IpPrefix(addr, prefix))
            }
            // IPv6 private/local
            for ((addr, prefix) in LOCAL_NETWORK_EXCLUSIONS_V6) {
                builder.excludeRoute(android.net.IpPrefix(addr, prefix))
            }
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
                underlyingNetworkSet = false
                if (network != previous && isRunning) {
                    Log.i(TAG, "Default network changed: $previous -> $network, restarting tunnel")
                    setUnderlyingNetworks(arrayOf(network))
                    underlyingNetworkSet = true
                    restartTunnel()
                }
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Default network lost: $network")
                if (currentNetwork == network) {
                    currentNetwork = null
                    if (isRunning) {
                        setUnderlyingNetworks(null)
                        restartTunnel()
                    }
                }
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                // Only update once per network — this callback fires very frequently
                // (signal changes, bandwidth updates, etc.) and each setUnderlyingNetworks
                // call wakes the system. We only need it once to confirm validation.
                if (network == currentNetwork && isRunning && !underlyingNetworkSet &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    underlyingNetworkSet = true
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
