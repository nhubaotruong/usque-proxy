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
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.R
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
import kotlinx.coroutines.runBlocking
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
            }
            DnsMode.CLOUDFLARE -> {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("2606:4700:4700::1111")
            }
            DnsMode.CUSTOM_DOH -> {
                builder.addDnsServer("10.255.255.53")
                builder.addRoute("10.255.255.53", 32)
                config.put("doh_url", prefs.dohUrl)
            }
        }

        val configJson = config.toString()

        // Local network bypass
        if (prefs.bypassLocalNetwork) {
            if (Build.VERSION.SDK_INT >= 33) {
                // Must add routes first, then exclude
                builder.addRoute("0.0.0.0", 0)
                builder.addRoute("::", 0)
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("10.0.0.0"), 8))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("172.16.0.0"), 12))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("192.168.0.0"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("169.254.0.0"), 16))
                // 127.0.0.0/8 not needed — loopback is never routed through VPN
            } else {
                // API 31-32: use additive public routes instead
                addPublicRoutes(builder)
            }
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
    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        var currentNetwork: Network? = cm.activeNetwork
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // Only restart if the active network actually changed (WiFi ↔ cellular).
                // onAvailable fires on initial registration too, so skip if same network.
                if (currentNetwork != null && network != currentNetwork && isRunning) {
                    Log.i(TAG, "Network changed: $currentNetwork -> $network, restarting tunnel")
                    setUnderlyingNetworks(arrayOf(network))
                    restartTunnel()
                }
                currentNetwork = network
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Network lost: $network")
                currentNetwork = null
                // Don't restart here — wait for onAvailable with a new network.
                // The Go-side exponential backoff handles the gap gracefully.
            }
        }
        cm.registerNetworkCallback(request, callback)
        networkCallback = callback
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            runCatching { cm.unregisterNetworkCallback(it) }
            networkCallback = null
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
        // IPv4 public ranges (skip 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8)
        builder.addRoute("0.0.0.0", 5)      // 0-7
        builder.addRoute("8.0.0.0", 7)      // 8-9
        builder.addRoute("11.0.0.0", 8)     // 11
        for (i in 12..126) {                 // 12-126 (skip 127), handle 172.16/12
            if (i in 172..172) continue      // handle separately
            builder.addRoute("$i.0.0.0", 8)
        }
        builder.addRoute("128.0.0.0", 3)    // 128-159
        builder.addRoute("160.0.0.0", 5)    // 160-167
        builder.addRoute("168.0.0.0", 6)    // 168-171
        // 172.0-15 and 172.32-255
        builder.addRoute("172.0.0.0", 12)   // 172.0-15 (this overlaps, let's just be simpler)
        builder.addRoute("172.32.0.0", 11)  // 172.32-63
        builder.addRoute("172.64.0.0", 10)  // 172.64-127
        builder.addRoute("172.128.0.0", 9)  // 172.128-255
        for (i in 173..191) {
            if (i == 192) continue
            builder.addRoute("$i.0.0.0", 8)
        }
        builder.addRoute("192.0.0.0", 9)    // 192.0-127
        builder.addRoute("192.128.0.0", 11) // 192.128-159
        builder.addRoute("192.160.0.0", 13) // 192.160-167
        builder.addRoute("192.169.0.0", 16) // 192.169
        builder.addRoute("192.170.0.0", 15) // 192.170-171
        builder.addRoute("192.172.0.0", 14) // 192.172-175
        builder.addRoute("192.176.0.0", 12) // 192.176-191
        builder.addRoute("192.192.0.0", 10) // 192.192-255
        builder.addRoute("193.0.0.0", 8)
        for (i in 194..223) builder.addRoute("$i.0.0.0", 8)
        // IPv6 all
        builder.addRoute("::", 0)
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
