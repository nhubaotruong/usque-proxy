package com.nhubaotruong.usqueproxy.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
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
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.yield
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject
import usquebind.Usquebind
import usquebind.VpnProtector

class UsqueVpnService : VpnService() {

    companion object {
        const val TAG = "UsqueVpnService"
        const val ACTION_STOP = "com.nhubaotruong.usqueproxy.STOP_VPN"
        const val ACTION_RESTART = "com.nhubaotruong.usqueproxy.RESTART_VPN"
        const val CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 1
        private const val WATCHDOG_INTERVAL_MS = 60_000L
        private const val ERROR_GRACE_TICKS = 3 // suppress errors for 3 watchdog intervals (~3 min)

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var lastError: String? = null
            private set

        fun clearError() { lastError = null }

        /** Event emitted on VPN state changes — ViewModel collects instead of polling. */
        sealed interface VpnServiceEvent {
            data object Connecting : VpnServiceEvent
            data object Started : VpnServiceEvent
            data object Stopped : VpnServiceEvent
            data object Disconnecting : VpnServiceEvent
            data class Error(val message: String) : VpnServiceEvent
        }

        private val _events = MutableSharedFlow<VpnServiceEvent>(replay = 1, extraBufferCapacity = 16)
        val events: SharedFlow<VpnServiceEvent> = _events.asSharedFlow()

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
    private var tunnelJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var startJob: Job? = null
    @Volatile
    private var currentNetwork: Network? = null
    @Volatile
    private var underlyingNetworkSet = false
    @Volatile
    private var isDeviceIdle = false
    private var lastWatchdogRxTx: Long = 0L
    private var watchdogStallCount: Int = 0
    private var errorGraceCount: Int = 0 // suppress transient errors during reconnect
    private var lastSurfacedError: String = ""
    @Volatile
    private var isManagedShutdown = false // true during stopVpnInternal, prevents self-stop in tunnelJob finally
    @Volatile
    private var isPowerSaveMode = false

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val lifecycleMutex = Mutex()

    private val powerManager by lazy { getSystemService(Context.POWER_SERVICE) as PowerManager }
    private val connectWakeLock by lazy {
        powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "UsqueProxy:connect")
            .apply { setReferenceCounted(false) }
    }

    private val idleModeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                    val idle = powerManager.isDeviceIdleMode
                    val wasIdle = isDeviceIdle
                    isDeviceIdle = idle
                    if (wasIdle && !idle && isRunning) {
                        Log.i(TAG, "Exiting Doze mode, triggering reconnect")
                        restartTunnel()
                    }
                }
                PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> {
                    val saving = powerManager.isPowerSaveMode
                    Log.i(TAG, "Power Save Mode: $saving")
                    // In power save mode, increase reconnect debounce to reduce wake-ups
                    isPowerSaveMode = saving
                }
            }
        }
    }

    private val reconnectWakeLock by lazy {
        powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "UsqueProxy:reconnect")
            .apply { setReferenceCounted(false) }
    }

    private val reconnectHandler = Handler(Looper.getMainLooper())
    private val reconnectRunnable = Runnable {
        if (isRunning && !isDeviceIdle) {
            reconnectWakeLock.acquire(30_000L) // 30s max for reconnect handshake
            try {
                Usquebind.reconnect()
            } finally {
                if (reconnectWakeLock.isHeld) reconnectWakeLock.release()
            }
        }
    }
    private val watchdogRunnable = object : Runnable {
        override fun run() {
            if (!isRunning) return
            runCatching {
                // getStats() is a JNI call that reads atomics — should be fast,
                // but add a safety timeout to prevent blocking the main handler.
                val statsJson = java.util.concurrent.FutureTask<String> { Usquebind.getStats() }
                    .also { Thread(it, "usque-stats").start() }
                    .runCatching { get(2, java.util.concurrent.TimeUnit.SECONDS) }
                    .getOrNull() ?: return@runCatching
                val stats = JSONObject(statsJson)
                val goConnected = stats.optBoolean("connected", false)
                val goRunning = stats.optBoolean("running", false)
                val rxTx = stats.optLong("rx_bytes", 0) + stats.optLong("tx_bytes", 0)
                val goHasNetwork = stats.optBoolean("has_network", true)
                val lastErr = stats.optString("last_error", "")

                // Surface Go-side errors to the UI, but only after a grace period
                // to suppress transient errors during normal reconnect cycles.
                // Like ProtonVPN's "fail countdown" — wait for ERROR_GRACE_TICKS
                // consecutive error ticks before surfacing to avoid UI flicker.
                if (goConnected) {
                    errorGraceCount = 0
                    lastSurfacedError = ""
                    updateNotification("VPN is active")
                } else if (lastErr.isNotEmpty() && goRunning) {
                    errorGraceCount++
                    if (errorGraceCount >= ERROR_GRACE_TICKS && lastErr != lastSurfacedError) {
                        lastError = lastErr
                        lastSurfacedError = lastErr
                        _events.tryEmit(VpnServiceEvent.Error(lastErr))
                    }
                    if (!goHasNetwork) {
                        updateNotification("Waiting for network...")
                    } else {
                        updateNotification("Reconnecting...")
                    }
                } else if (goRunning && !goHasNetwork) {
                    errorGraceCount = 0
                    updateNotification("Waiting for network...")
                } else if (goRunning) {
                    errorGraceCount = 0
                    updateNotification("Reconnecting...")
                }

                // Stuck detection: tunnel says connected but no traffic for 2+ intervals
                if (goConnected && rxTx > 0L && rxTx == lastWatchdogRxTx) {
                    watchdogStallCount++
                    if (watchdogStallCount >= 3) { // 3 intervals = ~3 min stall
                        Log.w(TAG, "Stuck connection detected (no traffic for ${watchdogStallCount * WATCHDOG_INTERVAL_MS / 1000}s), triggering reconnect")
                        Usquebind.reconnect()
                        watchdogStallCount = 0
                    }
                } else {
                    watchdogStallCount = 0
                }
                lastWatchdogRxTx = rxTx
            }
            reconnectHandler.postDelayed(this, WATCHDOG_INTERVAL_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        registerReceiver(
            idleModeReceiver,
            IntentFilter().apply {
                addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
            },
            Context.RECEIVER_NOT_EXPORTED
        )
        isDeviceIdle = powerManager.isDeviceIdleMode
        isPowerSaveMode = powerManager.isPowerSaveMode
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when {
            // OS restarted service after process death — restore tunnel from prefs
            intent == null -> {
                Log.i(TAG, "Process restore: re-establishing tunnel from saved preferences")
                startForeground(NOTIFICATION_ID, buildNotification())
                launchStartJob()
                return START_STICKY
            }
            intent.action == ACTION_STOP -> {
                serviceScope.launch { stopVpnInternal() }
                return START_NOT_STICKY
            }
            intent.action == ACTION_RESTART -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                serviceScope.launch {
                    stopVpnInternal()
                    yield() // allow cancellation between stop and start
                    launchStartJob()
                }
                return START_STICKY
            }
            // Always-On VPN: system starts service with VpnService.SERVICE_INTERFACE action
            intent.action == SERVICE_INTERFACE -> {
                Log.i(TAG, "Always-On VPN triggered by system")
                startForeground(NOTIFICATION_ID, buildNotification())
                launchStartJob()
                return START_STICKY
            }
            else -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                launchStartJob()
                return START_STICKY
            }
        }
    }

    private fun launchStartJob() {
        startJob?.cancel()
        _events.tryEmit(VpnServiceEvent.Connecting)
        updateNotification("Connecting...")
        connectWakeLock.acquire(2 * 60 * 1000L) // 2-minute max to prevent leaks
        startJob = serviceScope.launch {
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

        // Detect Android Private DNS (DNS-over-TLS) — when active, the system resolves
        // DNS directly via its Private DNS provider, potentially bypassing our tunnel DNS.
        // Log it so the user understands DNS behavior, and pass the flag to Go.
        val privateDnsActive = isPrivateDnsActive()
        if (privateDnsActive) {
            Log.i(TAG, "Android Private DNS is active — system DNS queries may bypass tunnel DNS interception")
            config.put("private_dns_active", true)
        }

        // DNS
        when (prefs.dnsMode) {
            DnsMode.SYSTEM -> {
                val dns = getSystemDnsServers()
                Log.d(TAG, "Using system DNS (protected forwarding): $dns")
                // Pass system DNS servers to Go for protected socket forwarding
                config.put("system_dns", JSONArray(dns))
                dns.forEach { addr ->
                    builder.addDnsServer(addr)
                    // Keep excludeRoute as optimization (reduces TUN traffic when it works)
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
            }
            DnsMode.CUSTOM_DOH -> {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("2606:4700:4700::1111")
                config.put("doh_url", prefs.dohUrl)
            }
            DnsMode.CUSTOM_DOQ -> {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("2606:4700:4700::1111")
                config.put("doq_url", prefs.doqUrl)
            }
        }

        // Pass current network type for adaptive keepalive
        config.put("network_type", detectNetworkType())

        val configJson = config.toString()

        // Routes: catch-all + exclusions
        builder.addRoute("0.0.0.0", 0)
        builder.addRoute("::", 0)

        if (prefs.bypassLocalNetwork) {
            excludeLocalNetworks(builder)
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
            // establish() returns null when: VPN permission not granted, another VPN
            // is active, or the app was put in a restricted background state.
            val reason = if (prepare(this@UsqueVpnService) != null)
                "VPN permission not granted or another VPN is active"
            else
                "Failed to establish VPN interface"
            Log.e(TAG, reason)
            lastError = reason
            _events.tryEmit(VpnServiceEvent.Error(reason))
            withContext(Dispatchers.Main) { stopSelf() }
            return
        }

        // Wait for system to validate the tunnel network before sending traffic.
        // Apps making TLS connections immediately after VPN start may fail on newer
        // Android versions if the network isn't validated yet.
        waitForTunnelVerified(cm)

        val fd = vpnInterface!!.fd
        isRunning = true
        Log.i(TAG, "VPN established: always-on=$isAlwaysOn, lockdown=$isLockdownEnabled")
        _events.tryEmit(VpnServiceEvent.Started)
        updateNotification("VPN is active")
        VpnTileService.requestUpdate(this)

        val protector = object : VpnProtector {
            override fun protectFd(fd: Long): Boolean {
                return protect(fd.toInt())
            }
        }

        tunnelJob = serviceScope.launch {
            try {
                Usquebind.startTunnel(configJson, fd.toLong(), protector)
            } catch (e: Throwable) {
                Log.e(TAG, "Tunnel error", e)
                lastError = e.message ?: "Tunnel failed"
                _events.tryEmit(VpnServiceEvent.Error(lastError!!))
            } finally {
                isRunning = false
                _events.tryEmit(VpnServiceEvent.Stopped)
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

        registerNetworkCallback()
        startWatchdog()
    }

    private fun startWatchdog() {
        lastWatchdogRxTx = 0L
        watchdogStallCount = 0
        reconnectHandler.removeCallbacks(watchdogRunnable)
        reconnectHandler.postDelayed(watchdogRunnable, WATCHDOG_INTERVAL_MS)
    }

    private fun stopWatchdog() {
        reconnectHandler.removeCallbacks(watchdogRunnable)
    }

    /**
     * Tracks the system default network via [ConnectivityManager.registerDefaultNetworkCallback].
     * Fires reliably on WiFi ↔ cellular switches, even in background (foreground service).
     */
    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        currentNetwork = cm.activeNetwork
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val previous = currentNetwork
                currentNetwork = network
                underlyingNetworkSet = false
                cm.getNetworkCapabilities(network)?.let { updateNetworkHint(it) }
                if (isRunning) {
                    setUnderlyingNetworks(arrayOf(network))
                    underlyingNetworkSet = true
                    // Tell Go side network is available — it triggers reconnect internally
                    // if it was waiting. Only force Android-side reconnect if network changed.
                    Usquebind.setConnectivity(true)
                    if (network != previous) {
                        Log.i(TAG, "Default network changed: $previous -> $network")
                        restartTunnel()
                    }
                }
            }

            override fun onLosing(network: Network, maxMsToLive: Int) {
                // Network handoff in progress — new network should arrive via onAvailable.
                Log.d(TAG, "Network losing: $network (${maxMsToLive}ms to live)")
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Default network lost: $network")
                if (currentNetwork == network) {
                    currentNetwork = null
                    if (isRunning) {
                        setUnderlyingNetworks(null)
                        // Don't trigger reconnect — the Go side will detect the broken
                        // connection and wait for SetConnectivity(true) instead of
                        // hammering failed dials. This saves significant battery.
                        Usquebind.setConnectivity(false)
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
                    updateNetworkHint(caps)
                }
            }
        }
        cm.registerDefaultNetworkCallback(callback)
        networkCallback = callback
    }

    /**
     * Waits up to 500ms for the system to validate the VPN tunnel network.
     * Ensures NET_CAPABILITY_VALIDATED is set before apps start using the tunnel,
     * preventing TLS failures on newer Android versions.
     */
    private fun waitForTunnelVerified(cm: ConnectivityManager) {
        val latch = java.util.concurrent.CountDownLatch(1)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
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

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            runCatching { cm.unregisterNetworkCallback(it) }
            networkCallback = null
            currentNetwork = null
        }
    }

    private fun restartTunnel() {
        // Debounce rapid network changes (WiFi↔cellular) into a single reconnect.
        // Double the delay in Power Save Mode to reduce wake-ups.
        val delay = if (isPowerSaveMode) 4000L else 2000L
        reconnectHandler.removeCallbacks(reconnectRunnable)
        reconnectHandler.postDelayed(reconnectRunnable, delay)
    }

    /**
     * Performs full VPN shutdown. Serialized via [lifecycleMutex] to prevent
     * concurrent start/stop races.
     */
    private suspend fun stopVpnInternal() {
        // Cancel startJob BEFORE acquiring mutex to avoid deadlock:
        // startJob holds mutex during setup, stop needs mutex for teardown.
        startJob?.cancel()
        startJob = null
        lifecycleMutex.withLock {
        isManagedShutdown = true
        try {
        _events.tryEmit(VpnServiceEvent.Disconnecting)
        updateNotification("Disconnecting...")
        reconnectHandler.removeCallbacks(reconnectRunnable)
        stopWatchdog()
        unregisterNetworkCallback()
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
        isRunning = false
        _events.tryEmit(VpnServiceEvent.Stopped)
        VpnTileService.requestUpdate(this)
        withContext(Dispatchers.Main) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
        } finally {
            isManagedShutdown = false
        }
        } // lifecycleMutex.withLock
    }

    override fun onDestroy() {
        reconnectHandler.removeCallbacks(reconnectRunnable)
        stopWatchdog()
        runCatching { unregisterReceiver(idleModeReceiver) }
        // Synchronous cleanup: stop tunnel and cancel scope
        Usquebind.stopTunnel()
        tunnelJob?.cancel()
        vpnInterface?.close()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        // Synchronous cleanup — onRevoke may be followed immediately by onDestroy
        reconnectHandler.removeCallbacks(reconnectRunnable)
        stopWatchdog()
        unregisterNetworkCallback()
        Usquebind.stopTunnel()
        tunnelJob?.cancel()
        vpnInterface?.close()
        vpnInterface = null
        isRunning = false
        _events.tryEmit(VpnServiceEvent.Stopped)
        VpnTileService.requestUpdate(this)
        super.onRevoke()
    }

    /**
     * Excludes local networks from the VPN tunnel. First tries to discover actual
     * local subnets dynamically (like ProtonVPN), then falls back to hardcoded
     * RFC1918/link-local ranges. Dynamic detection is better because it uses the
     * exact prefix length of the user's local network (e.g., /24) instead of
     * overly broad ranges (e.g., 192.168.0.0/16).
     */
    private fun excludeLocalNetworks(builder: Builder) {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val dynamicExclusions = mutableListOf<IpPrefix>()

        // Discover actual local network subnets from all non-VPN, non-cellular networks
        runCatching {
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                val lp = cm.getLinkProperties(network) ?: continue
                for (la in lp.linkAddresses) {
                    val addr = la.address
                    val prefix = la.prefixLength
                    // Only include private/link-local addresses
                    if (addr.isLinkLocalAddress || addr.isSiteLocalAddress ||
                        addr.isLoopbackAddress || isPrivateAddress(addr)
                    ) {
                        dynamicExclusions.add(IpPrefix(addr, prefix))
                    }
                }
            }
        }

        if (dynamicExclusions.isNotEmpty()) {
            Log.d(TAG, "Excluding ${dynamicExclusions.size} dynamically detected local networks")
            for (prefix in dynamicExclusions) {
                runCatching { builder.excludeRoute(prefix) }
            }
        }

        // Always add static ranges for subnets we're not currently connected to
        // (e.g., other private ranges, multicast, broadcast)
        for ((addr, prefix) in LOCAL_NETWORK_EXCLUSIONS_V4) {
            runCatching { builder.excludeRoute(IpPrefix(addr, prefix)) }
        }
        for ((addr, prefix) in LOCAL_NETWORK_EXCLUSIONS_V6) {
            runCatching { builder.excludeRoute(IpPrefix(addr, prefix)) }
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

    private fun isPrivateDnsActive(): Boolean = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val lp = cm.getLinkProperties(network) ?: return false
        lp.isPrivateDnsActive && lp.privateDnsServerName != null
    } catch (_: Exception) {
        false
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

    private fun updateNetworkHint(caps: NetworkCapabilities) {
        val hint = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            else -> ""
        }
        Usquebind.setNetworkHint(hint)
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

    private fun updateNotification(status: String) {
        runCatching {
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(NOTIFICATION_ID, buildNotification(status))
        }
    }

    private fun buildNotification(status: String = "VPN is active"): Notification {
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
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_vpn_tile)
            .setContentIntent(openPending)
            .addAction(Notification.Action.Builder(null, "Disconnect", stopPending).build())
            .setOngoing(true)
            .build()
    }
}
