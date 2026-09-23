package com.nhubaotruong.usqueproxy.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import com.nhubaotruong.usqueproxy.data.DnsMode
import com.nhubaotruong.usqueproxy.data.Office365Endpoints
import com.nhubaotruong.usqueproxy.data.SplitMode
import com.nhubaotruong.usqueproxy.data.VpnPreferences
import com.nhubaotruong.usqueproxy.data.VpnPrefs
import com.nhubaotruong.usqueproxy.tile.VpnTileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import org.json.JSONObject
import usquebind.TunnelListener
import usquebind.Usquebind

class UsqueVpnService :
    VpnService(),
    TunnelListener {
    companion object {
        const val TAG = "UsqueVpnService"
        const val ACTION_STOP = "com.nhubaotruong.usqueproxy.STOP_VPN"
        const val ACTION_RESTART = "com.nhubaotruong.usqueproxy.RESTART_VPN"

        // Pre-computed IpPrefix exclusions — avoids InetAddress.getByName() on every VPN start
        private val LOCAL_NETWORK_EXCLUSIONS_V4: List<Pair<java.net.InetAddress, Int>> by lazy {
            listOf(
                "10.0.0.0" to 8,
                "169.254.0.0" to 16, // Link-local
                "172.16.0.0" to 12,
                "192.0.0.0" to 24,
                "192.168.0.0" to 16,
                "224.0.0.0" to 24, // Local multicast
                "240.0.0.0" to 4, // Reserved
                "255.255.255.255" to 32, // Broadcast
            ).map { (addr, prefix) -> java.net.InetAddress.getByName(addr) to prefix }
        }

        private val LOCAL_NETWORK_EXCLUSIONS_V6: List<Pair<java.net.InetAddress, Int>> by lazy {
            listOf(
                "fd00::" to 8, // ULA
                "fe80::" to 10, // Link-local
                "ff01::" to 16, // Interface-local multicast
                "ff02::" to 16, // Link-local multicast
                "ff03::" to 16, // Realm-local multicast
                "ff04::" to 16, // Admin-local multicast
                "ff05::" to 16, // Site-local multicast
            ).map { (addr, prefix) -> java.net.InetAddress.getByName(addr) to prefix }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelJob: Job? = null
    private var startJob: Job? = null

    @Volatile
    private var isManagedShutdown = false // true during stopVpnInternal, prevents self-stop in tunnelJob finally

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val lifecycleMutex = Mutex()

    private val notification by lazy { VpnNotification(this) }
    private val networkWatcher by lazy {
        NetworkWatcher(
            this,
            onUnderlyingNetworks = { networks ->
                if (TunnelStateHolder.isRunning) setUnderlyingNetworks(networks)
            },
        )
    }

    private val powerManager by lazy { getSystemService(Context.POWER_SERVICE) as PowerManager }
    private val connectWakeLock by lazy {
        powerManager
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "UsqueProxy:connect")
            .apply { setReferenceCounted(false) }
    }

    override fun onCreate() {
        super.onCreate()
        // VpnNotification init creates the channel.
        notification
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        when {
            // OS restarted service after process death — restore tunnel from prefs
            intent == null -> {
                Log.i(TAG, "Process restore: re-establishing tunnel from saved preferences")
                startForeground(VpnNotification.NOTIFICATION_ID, notification.buildConnecting())
                launchStartJob()
                return START_STICKY
            }

            intent.action == ACTION_STOP -> {
                serviceScope.launch { stopVpnInternal() }
                return START_NOT_STICKY
            }

            intent.action == ACTION_RESTART -> {
                startForeground(VpnNotification.NOTIFICATION_ID, notification.buildConnecting())
                serviceScope.launch {
                    // Keep the service alive across the restart: stopSelf() inside
                    // stopVpnInternal() would destroy it and cancel this scope before
                    // launchStartJob() runs, leaving the VPN dead.
                    stopVpnInternal(stopService = false)
                    yield() // allow cancellation between stop and start
                    launchStartJob()
                }
                return START_STICKY
            }

            // Always-On VPN: system starts service with VpnService.SERVICE_INTERFACE action
            intent.action == SERVICE_INTERFACE -> {
                Log.i(TAG, "Always-On VPN triggered by system")
                startForeground(VpnNotification.NOTIFICATION_ID, notification.buildConnecting())
                launchStartJob()
                return START_STICKY
            }

            else -> {
                startForeground(VpnNotification.NOTIFICATION_ID, notification.buildConnecting())
                launchStartJob()
                return START_STICKY
            }
        }
    }

    private fun launchStartJob() {
        startJob?.cancel()
        // Set before the tunnel job launches — the dead-man's switch and UI both read it.
        TunnelStateHolder.isRunning = true
        TunnelStateHolder.emit(VpnServiceEvent.Connecting)
        notification.showConnecting()
        connectWakeLock.acquire(2 * 60 * 1000L) // 2-minute max to prevent leaks
        startJob =
            serviceScope.launch {
                try {
                    // Serialize with stopVpnInternal to prevent start/stop races
                    lifecycleMutex.withLock {
                        ensureActive() // throw CancellationException if cancelled while waiting for lock
                        val prefs = VpnPreferences(this@UsqueVpnService).prefsFlow.first()

                        if (!prefs.isActiveRegistered || prefs.activeConfigJson.isEmpty()) {
                            Log.e(TAG, "No config found for active profile, stopping")
                            withContext(Dispatchers.Main) { stopSelf() }
                            return@withLock
                        }

                        // Refresh Office 365 endpoint cache before starting VPN
                        if (prefs.bypassOffice365) {
                            runCatching { Office365Endpoints.refreshCache(this@UsqueVpnService) }
                        }

                        startVpn(prefs)
                    }
                } finally {
                    if (connectWakeLock.isHeld) connectWakeLock.release()
                }
            }
    }

    private suspend fun startVpn(prefs: VpnPrefs) {
        val builder =
            Builder()
                .setMtu(1280)
                .setSession("UsqueProxy")
                .setMetered(prefs.isMetered)

        // Addresses from config
        val config = JSONObject(prefs.activeConfigJson)
        config.optString("ipv4", "").takeIf { it.isNotEmpty() }?.let {
            builder.addAddress(it, 32)
        }
        config.optString("ipv6", "").takeIf { it.isNotEmpty() }?.let {
            builder.addAddress(it, 128)
        }

        // Read the underlying network's LinkProperties once and derive both Private DNS
        // status and system DNS servers from the same snapshot. Two separate callbacks
        // could race against Private DNS bootstrap and produce inconsistent state, which
        // left tunnel DNS broken until the user toggled Private DNS off and on again.
        val cmEarly = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val underlyingLp = underlyingLinkProperties(cmEarly)
        val privateDnsActive =
            underlyingLp?.let {
                it.isPrivateDnsActive && it.privateDnsServerName != null
            } ?: false
        if (privateDnsActive) {
            Log.i(TAG, "Android Private DNS is active — system DNS queries may bypass tunnel DNS interception")
        }

        // Excluded prefixes for userspace route exclusion on API < 33, where
        // VpnService.Builder.excludeRoute does not exist (kernel exclusions
        // are skipped there too). The Go tunnel relays matching traffic
        // directly via protected sockets instead of through the VPN.
        val excludePrefixes = mutableListOf<String>()

        // DNS
        val systemDns = systemDnsServersFrom(underlyingLp)
        when (prefs.dnsMode) {
            DnsMode.SYSTEM -> {
                Log.d(TAG, "Using system DNS (protected forwarding): $systemDns")
                systemDns.forEach { addr ->
                    builder.addDnsServer(addr)
                    // Keep excludeRoute as optimization (reduces TUN traffic when it works)
                    runCatching {
                        val inet = java.net.InetAddress.getByName(addr)
                        val prefix = if (inet is java.net.Inet6Address) 128 else 32
                        excludePrefixes += "$addr/$prefix"
                        builder.excludeRouteCompat(inet, prefix)
                    }.onFailure { e ->
                        Log.w(TAG, "Failed to exclude DNS route $addr: ${e.message}")
                    }
                }
            }

            DnsMode.CLOUDFLARE -> {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("2606:4700:4700::1111")
            }

            DnsMode.CUSTOM_DOH -> {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("2606:4700:4700::1111")
            }

            DnsMode.CUSTOM_DOQ -> {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("2606:4700:4700::1111")
            }
        }

        var configJson =
            TunnelConfigBuilder.build(
                prefs,
                privateDnsActive = privateDnsActive,
                systemDns = systemDns,
                networkType = detectNetworkType(),
            )

        // Routes: catch-all + exclusions
        builder.addRoute("0.0.0.0", 0)
        builder.addRoute("::", 0)

        if (prefs.bypassLocalNetwork) {
            excludeLocalNetworks(builder, excludePrefixes)
        }

        if (prefs.bypassOffice365) {
            val o365Ips = Office365Endpoints.getIpRanges(this)
            Log.d(TAG, "Excluding ${o365Ips.size} Office 365 IP ranges from VPN")
            for (cidr in o365Ips) {
                runCatching {
                    val parts = cidr.split("/")
                    val addr = java.net.InetAddress.getByName(parts[0])
                    val prefix = parts[1].toInt()
                    builder.excludeRouteCompat(addr, prefix)
                    excludePrefixes += cidr
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

        // API < 33: the framework has no excludeRoute, so pass the excluded
        // prefixes to the Go tunnel, which relays them directly via protected
        // sockets (userspace route exclusion). On 33+ the kernel excludes the
        // routes and no matching packets reach the TUN, so this is not needed.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU && excludePrefixes.isNotEmpty()) {
            runCatching {
                val json = org.json.JSONObject(configJson)
                json.put("exclude_prefixes", org.json.JSONArray(excludePrefixes))
                configJson = json.toString()
                Log.i(TAG, "Userspace route exclusion (${excludePrefixes.size} prefixes)")
            }.onFailure { e ->
                Log.w(TAG, "Failed to add exclude_prefixes to tunnel config: ${e.message}")
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
            // establish() returns null when: VPN permission not granted, another VPN
            // is active, or the app was put in a restricted background state.
            val reason =
                if (prepare(this@UsqueVpnService) != null) {
                    "VPN permission not granted or another VPN is active"
                } else {
                    "Failed to establish VPN interface"
                }
            Log.e(TAG, reason)
            TunnelStateHolder.lastError = reason
            TunnelStateHolder.emit(VpnServiceEvent.Error(reason))
            notification.showError(reason)
            withContext(Dispatchers.Main) { stopSelf() }
            return
        }

        // Wait for system to validate the tunnel network before sending traffic.
        // Apps making TLS connections immediately after VPN start may fail on newer
        // Android versions if the network isn't validated yet.
        waitForTunnelVerified(cm)

        val fd = vpnInterface!!.fd
        Log.i(TAG, "VPN established: always-on=$isAlwaysOn, lockdown=$isLockdownEnabled")
        TunnelStateHolder.emit(VpnServiceEvent.Started)
        notification.showConnected()
        VpnTileService.requestUpdate(this)

        tunnelJob =
            serviceScope.launch {
                try {
                    Usquebind.startTunnel(configJson, fd.toLong(), this@UsqueVpnService)
                } catch (e: Throwable) {
                    Log.e(TAG, "Tunnel error", e)
                    val msg = e.message ?: "Tunnel failed"
                    TunnelStateHolder.lastError = msg
                    TunnelStateHolder.emit(VpnServiceEvent.Error(msg))
                } finally {
                    TunnelStateHolder.isRunning = false
                    TunnelStateHolder.emit(VpnServiceEvent.Stopped)
                    VpnTileService.requestUpdate(this@UsqueVpnService)
                    // Only self-stop if not in a managed stop — during those,
                    // stopVpnInternal() handles the lifecycle.
                    // Use Handler.post (non-suspending) to avoid CancellationException
                    // inside finally if the coroutine was cancelled.
                    if (!isManagedShutdown) {
                        Handler(Looper.getMainLooper()).post { stopSelf() }
                    }
                }
            }

        networkWatcher.register()
    }

    /**
     * Performs full VPN shutdown. Serialized via [lifecycleMutex] to prevent
     * concurrent start/stop races.
     */
    private suspend fun stopVpnInternal(stopService: Boolean = true) {
        // Cancel startJob BEFORE acquiring mutex to avoid deadlock:
        // startJob holds mutex during setup, stop needs mutex for teardown.
        startJob?.cancel()
        startJob = null
        lifecycleMutex.withLock {
            isManagedShutdown = true
            try {
                TunnelStateHolder.emit(VpnServiceEvent.Disconnecting)
                notification.showDisconnecting()
                networkWatcher.unregister()
                Usquebind.stopTunnel()
                // Wait up to 3s for tunnel to shut down gracefully; cancel if it hangs
                withTimeoutOrNull(3000L) { tunnelJob?.join() }
                    ?: run {
                        Log.w(TAG, "Tunnel job did not finish within 3s, cancelling")
                        tunnelJob?.cancel()
                    }
                tunnelJob = null
                vpnInterface?.close()
                vpnInterface = null
                TunnelStateHolder.isRunning = false
                TunnelStateHolder.emit(VpnServiceEvent.Stopped)
                VpnTileService.requestUpdate(this)
                if (stopService) {
                    withContext(Dispatchers.Main) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }
            } finally {
                isManagedShutdown = false
            }
        } // lifecycleMutex.withLock
    }

    override fun onDestroy() {
        // Synchronous cleanup: stop tunnel and cancel scope
        Usquebind.stopTunnel()
        tunnelJob?.cancel()
        vpnInterface?.close()
        TunnelStateHolder.isRunning = false
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        // Synchronous cleanup — onRevoke may be followed immediately by onDestroy
        networkWatcher.unregister()
        Usquebind.stopTunnel()
        tunnelJob?.cancel()
        vpnInterface?.close()
        vpnInterface = null
        TunnelStateHolder.isRunning = false
        TunnelStateHolder.emit(VpnServiceEvent.Stopped)
        VpnTileService.requestUpdate(this)
        super.onRevoke()
    }

    // --- TunnelListener (called from the Go tunnel goroutine) ---

    override fun onStateChanged(state: String) {
        when (val event = ListenerEventMapper.mapState(state)) {
            VpnServiceEvent.Connecting -> {
                TunnelStateHolder.emit(event)
            }

            VpnServiceEvent.Started -> {
                TunnelStateHolder.emit(event)
                notification.showConnected()
            }

            VpnServiceEvent.Disconnecting -> {
                TunnelStateHolder.emit(event)
            }

            VpnServiceEvent.Stopped -> {
                TunnelStateHolder.emit(event)
                notification.cancel()
            }

            null -> {
                Unit
            }

            else -> {
                Unit
            }
        }
    }

    override fun onStats(stats: String) {
        TunnelStateHolder.emit(VpnServiceEvent.Stats(parseTunnelStats(stats)))
    }

    override fun onError(err: String) {
        TunnelStateHolder.lastError = err
        ListenerEventMapper.mapError(err)?.let { event ->
            TunnelStateHolder.emit(event)
            notification.showError(err)
        }
    }

    /**
     * Waits up to 500ms for the system to validate the VPN tunnel network.
     * Ensures NET_CAPABILITY_VALIDATED is set before apps start using the tunnel,
     * preventing TLS failures on newer Android versions.
     */
    private fun waitForTunnelVerified(cm: ConnectivityManager) {
        val latch = java.util.concurrent.CountDownLatch(1)
        val cb =
            object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(
                    network: Network,
                    caps: NetworkCapabilities,
                ) {
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    ) {
                        latch.countDown()
                    }
                }
            }
        cm.registerDefaultNetworkCallback(cb)
        try {
            if (!latch.await(500, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                Log.d(TAG, "Tunnel verification timed out (500ms) — proceeding anyway")
            }
        } finally {
            runCatching { cm.unregisterNetworkCallback(cb) }
        }
    }

    /**
     * Excludes local networks from the VPN tunnel. First tries to discover actual
     * local subnets dynamically (like ProtonVPN), then falls back to hardcoded
     * RFC1918/link-local ranges. Dynamic detection is better because it uses the
     * exact prefix length of the user's local network (e.g., /24) instead of
     * overly broad ranges (e.g., 192.168.0.0/16).
     */
    private fun excludeLocalNetworks(
        builder: Builder,
        excludePrefixes: MutableList<String>,
    ) {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val dynamicExclusions = mutableListOf<Pair<java.net.InetAddress, Int>>()

        // Discover actual local network subnets from all non-VPN networks
        // using NetworkCallback (allNetworks is deprecated since API 31)
        runCatching {
            val discoveredNetworks = java.util.concurrent.ConcurrentLinkedQueue<Network>()
            val latch = java.util.concurrent.CountDownLatch(1)
            val request =
                NetworkRequest
                    .Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()
            val cb =
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        discoveredNetworks.add(network)
                    }
                }
            cm.registerNetworkCallback(request, cb)
            // Brief wait for callbacks to fire for already-connected networks
            latch.await(100, java.util.concurrent.TimeUnit.MILLISECONDS)
            runCatching { cm.unregisterNetworkCallback(cb) }

            for (network in discoveredNetworks) {
                val lp = cm.getLinkProperties(network) ?: continue
                for (la in lp.linkAddresses) {
                    val addr = la.address
                    val prefix = la.prefixLength
                    // Only include private/link-local addresses
                    if (addr.isLinkLocalAddress || addr.isSiteLocalAddress ||
                        addr.isLoopbackAddress || isPrivateAddress(addr)
                    ) {
                        dynamicExclusions.add(addr to prefix)
                    }
                }
            }
        }

        if (dynamicExclusions.isNotEmpty()) {
            Log.d(TAG, "Excluding ${dynamicExclusions.size} dynamically detected local networks")
            for (prefix in dynamicExclusions) {
                excludePrefixes += "${prefix.first.hostAddress}/${prefix.second}"
                runCatching { builder.excludeRouteCompat(prefix.first, prefix.second) }
            }
        }

        // Always add static ranges for subnets we're not currently connected to
        // (e.g., other private ranges, multicast, broadcast)
        for ((addr, prefix) in LOCAL_NETWORK_EXCLUSIONS_V4) {
            excludePrefixes += "${addr.hostAddress}/$prefix"
            runCatching { builder.excludeRouteCompat(addr, prefix) }
        }
        for ((addr, prefix) in LOCAL_NETWORK_EXCLUSIONS_V6) {
            excludePrefixes += "${addr.hostAddress}/$prefix"
            runCatching { builder.excludeRouteCompat(addr, prefix) }
        }
    }

    private fun isPrivateAddress(addr: java.net.InetAddress): Boolean {
        if (addr is java.net.Inet4Address) {
            val b = addr.address
            return (b[0].toInt() and 0xFF == 10) ||
                (b[0].toInt() and 0xFF == 172 && b[1].toInt() and 0xF0 == 16) ||
                (b[0].toInt() and 0xFF == 192 && b[1].toInt() and 0xFF == 168)
        }
        if (addr is java.net.Inet6Address) {
            val b = addr.address
            return b[0].toInt() and 0xFE == 0xFC // fd00::/7 (ULA)
        }
        return false
    }

    /**
     * excludeRoute exists only as excludeRoute(IpPrefix), which is API 33+ — the
     * String/InetAddress overloads were removed from the platform before API 30
     * (absent from stubs and runtime on API 30-32, verified against the API 30
     * framework). So route exclusions are simply unavailable on API 30-32; skip
     * them there. Fails soft (route not excluded) if a range is rejected.
     */
    private fun Builder.excludeRouteCompat(
        addr: java.net.InetAddress,
        prefixLength: Int,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            excludeRoute(IpPrefix(addr, prefixLength))
        } else {
            Log.d(TAG, "Route exclusion skipped (requires API 33+): $addr/$prefixLength")
        }
    }

    /**
     * Returns LinkProperties of the underlying (non-VPN) default network.
     *
     * Uses a short-lived NetworkCallback subscribing to onLinkPropertiesChanged
     * (NOT onAvailable + getLinkProperties): onLinkPropertiesChanged fires
     * synchronously at registration time with the network's CURRENT LP, so we
     * avoid a race where onAvailable arrives but getLinkProperties returns
     * stale/empty data while Private DNS (DoT) is still bootstrapping. That race
     * caused tunnel DNS to break on startup whenever Private DNS was active —
     * users had to toggle Private DNS off and on to recover.
     *
     * Also avoids reading ConnectivityManager.activeNetwork directly: when this
     * service restarts while the tunnel is still up, activeNetwork points at
     * the VPN itself and reports the VPN's own LinkProperties.
     */
    private fun underlyingLinkProperties(cm: ConnectivityManager): LinkProperties? {
        val result =
            java.util.concurrent.atomic
                .AtomicReference<LinkProperties?>(null)
        val latch = java.util.concurrent.CountDownLatch(1)
        val request =
            NetworkRequest
                .Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
        val cb =
            object : ConnectivityManager.NetworkCallback() {
                override fun onLinkPropertiesChanged(
                    network: Network,
                    lp: LinkProperties,
                ) {
                    if (result.compareAndSet(null, lp)) latch.countDown()
                }
            }
        runCatching {
            cm.registerNetworkCallback(request, cb)
            latch.await(1, java.util.concurrent.TimeUnit.SECONDS)
        }
        runCatching { cm.unregisterNetworkCallback(cb) }
        return result.get()
    }

    private fun systemDnsServersFrom(lp: LinkProperties?): List<String> {
        if (lp == null) return listOf("1.1.1.1")
        val servers = lp.dnsServers.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
        return servers.ifEmpty { listOf("1.1.1.1") }
    }

    private fun detectNetworkType(): String {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return ""
        val caps = cm.getNetworkCapabilities(network) ?: return ""
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            else -> ""
        }
    }
}
