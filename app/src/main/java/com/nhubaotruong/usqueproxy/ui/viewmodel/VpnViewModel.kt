package com.nhubaotruong.usqueproxy.ui.viewmodel

import android.app.Application
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.nhubaotruong.usqueproxy.data.AppInfo
import com.nhubaotruong.usqueproxy.data.AppRepository
import com.nhubaotruong.usqueproxy.data.DnsMode
import com.nhubaotruong.usqueproxy.data.ProfileType
import com.nhubaotruong.usqueproxy.data.SplitMode
import com.nhubaotruong.usqueproxy.data.ThemeMode
import com.nhubaotruong.usqueproxy.data.VpnPreferences
import com.nhubaotruong.usqueproxy.data.VpnPrefs
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import com.nhubaotruong.usqueproxy.vpn.TunnelStats
import com.nhubaotruong.usqueproxy.vpn.UsqueVpnService
import com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent
import com.nhubaotruong.usqueproxy.vpn.parseTunnelStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import usquebind.Usquebind

enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED }

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = VpnPreferences(application)
    private val appRepo = AppRepository(application)

    val vpnPrefs: StateFlow<VpnPrefs> = prefs.prefsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), VpnPrefs())

    private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
    val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

    private val _stats = MutableStateFlow(TunnelStats())
    val stats: StateFlow<TunnelStats> = _stats.asStateFlow()

    private val _connectedSince = MutableStateFlow<Long?>(null)
    val connectedSince: StateFlow<Long?> = _connectedSince.asStateFlow()

    private val _installedApps = MutableStateFlow<List<AppInfo>>(emptyList())
    val installedApps: StateFlow<List<AppInfo>> = _installedApps.asStateFlow()

    private val _registerError = MutableStateFlow<String?>(null)
    val registerError: StateFlow<String?> = _registerError.asStateFlow()

    private val _isRegistering = MutableStateFlow(false)
    val isRegistering: StateFlow<Boolean> = _isRegistering.asStateFlow()

    private val _needsRestart = MutableStateFlow(false)
    val needsRestart: StateFlow<Boolean> = _needsRestart.asStateFlow()

    private val _tunnelError = MutableStateFlow<String?>(null)
    val tunnelError: StateFlow<String?> = _tunnelError.asStateFlow()

    init {
        // Collect VPN service events for instant state updates (no polling needed).
        // Declared AFTER the MutableStateFlow properties: viewModelScope uses
        // Dispatchers.Main.immediate, so the collector can run synchronously during
        // construction, and the replay=1 SharedFlow delivers the last pending event
        // (e.g. a Stats event while the tunnel is running). Touching uninitialized
        // fields here would NPE on every app open.
        viewModelScope.launch {
            TunnelStateHolder.events.collect { event ->
                when (event) {
                    is VpnServiceEvent.Connecting -> {
                        _vpnState.value = VpnState.CONNECTING
                    }
                    is VpnServiceEvent.Started -> {
                        _vpnState.value = VpnState.CONNECTED
                    }
                    is VpnServiceEvent.Disconnecting -> {
                        // Keep current state — avoid UI flicker during brief disconnect
                    }
                    is VpnServiceEvent.Stopped -> {
                        _vpnState.value = VpnState.DISCONNECTED
                        _connectedSince.value = null
                        _needsRestart.value = false
                    }
                    is VpnServiceEvent.Error -> {
                        _tunnelError.value = event.message
                    }
                    is VpnServiceEvent.Stats -> {
                        _stats.value = event.stats
                        if (_connectedSince.value == null && event.stats.uptimeSec > 0) {
                            _connectedSince.value = System.currentTimeMillis() - event.stats.uptimeSec * 1000L
                        }
                    }
                }
            }
        }
    }
    fun clearTunnelError() { _tunnelError.value = null }

    companion object {
        const val STATE_POLL_INTERVAL = 1_000L
        const val STATS_POLL_INTERVAL = 2_000L
    }

    /** Called from composable LaunchedEffect — checks volatile booleans, no JNI. */
    fun refreshState() {
        val running = TunnelStateHolder.isRunning
        _vpnState.value = if (running) VpnState.CONNECTED else VpnState.DISCONNECTED
        if (!running) {
            _needsRestart.value = false
            _connectedSince.value = null
        }
        val error = TunnelStateHolder.lastError
        if (error != null) { _tunnelError.value = error; TunnelStateHolder.clearError() }
    }

    /** Called from composable LaunchedEffect — JNI getStats(), only when stats are visible. */
    suspend fun refreshStats() {
        val stats = withContext(Dispatchers.IO) {
            parseTunnelStats(Usquebind.getStats())
        }
        _stats.value = stats
        if (_connectedSince.value == null && stats.uptimeSec > 0) {
            _connectedSince.value = System.currentTimeMillis() - stats.uptimeSec * 1000L
        }
    }

    fun connect() {
        if (_vpnState.value != VpnState.DISCONNECTED) return
        _vpnState.value = VpnState.CONNECTING
        TunnelStateHolder.clearError()

        val ctx = getApplication<Application>()
        val intent = Intent(ctx, UsqueVpnService::class.java)
        ContextCompat.startForegroundService(ctx, intent)
    }

    fun disconnect() {
        val ctx = getApplication<Application>()
        val intent = Intent(ctx, UsqueVpnService::class.java).apply {
            action = UsqueVpnService.ACTION_STOP
        }
        ctx.startService(intent)
        _vpnState.value = VpnState.DISCONNECTED
        _connectedSince.value = null
        _needsRestart.value = false
    }

    fun restartVpn() {
        _vpnState.value = VpnState.CONNECTING
        _needsRestart.value = false
        TunnelStateHolder.clearError()
        val ctx = getApplication<Application>()
        val intent = Intent(ctx, UsqueVpnService::class.java).apply {
            action = UsqueVpnService.ACTION_RESTART
        }
        ContextCompat.startForegroundService(ctx, intent)
    }

    private fun markRestartNeeded() {
        if (TunnelStateHolder.isRunning) {
            _needsRestart.value = true
        }
    }

    fun register(license: String = "") {
        viewModelScope.launch {
            _isRegistering.value = true
            _registerError.value = null
            try {
                val configJson: String = withContext(Dispatchers.IO) {
                    Usquebind.register(license)
                }
                prefs.saveWarpConfig(configJson)
            } catch (e: Exception) {
                _registerError.value = e.message
            } finally {
                _isRegistering.value = false
            }
        }
    }

    fun registerWithJwt(jwt: String) {
        viewModelScope.launch {
            _isRegistering.value = true
            _registerError.value = null
            try {
                val configJson: String = withContext(Dispatchers.IO) {
                    Usquebind.registerWithJWT(jwt.trim())
                }
                prefs.saveZtConfig(configJson)
            } catch (e: Exception) {
                _registerError.value = e.message
            } finally {
                _isRegistering.value = false
            }
        }
    }

    fun enroll() {
        val p = vpnPrefs.value
        val activeConfig = p.activeConfigJson
        if (activeConfig.isEmpty()) return

        viewModelScope.launch {
            _isRegistering.value = true
            _registerError.value = null
            try {
                val updatedJson: String = withContext(Dispatchers.IO) {
                    Usquebind.enroll(activeConfig)
                }
                when (p.activeProfile) {
                    ProfileType.WARP -> prefs.saveWarpConfig(updatedJson)
                    ProfileType.ZERO_TRUST -> prefs.saveZtConfig(updatedJson)
                }
                markRestartNeeded()
            } catch (e: Exception) {
                _registerError.value = e.message
            } finally {
                _isRegistering.value = false
            }
        }
    }

    fun setActiveProfile(profile: ProfileType) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setActiveProfile(profile) }
    }

    fun clearRegistration() {
        viewModelScope.launch {
            when (vpnPrefs.value.activeProfile) {
                ProfileType.WARP -> prefs.clearWarpConfig()
                ProfileType.ZERO_TRUST -> prefs.clearZtConfig()
            }
        }
    }

    fun loadInstalledApps() {
        viewModelScope.launch {
            _installedApps.value = withContext(Dispatchers.IO) {
                appRepo.getInstalledApps()
            }
        }
    }

    fun setSplitMode(mode: SplitMode) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setSplitMode(mode) }
    }

//    fun setSelectedApps(apps: Set<String>) {
//        viewModelScope.launch { prefs.setSelectedApps(apps) }
//    }

    fun toggleApp(packageName: String) {
        markRestartNeeded()
        viewModelScope.launch {
            val p = vpnPrefs.value
            when (p.splitMode) {
                SplitMode.INCLUDE -> {
                    val updated = if (packageName in p.includedApps) p.includedApps - packageName else p.includedApps + packageName
                    prefs.setIncludedApps(updated)
                }
                SplitMode.EXCLUDE -> {
                    val updated = if (packageName in p.excludedApps) p.excludedApps - packageName else p.excludedApps + packageName
                    prefs.setExcludedApps(updated)
                }
                SplitMode.ALL -> { /* no-op */ }
            }
        }
    }

    fun setBypassLocalNetwork(bypass: Boolean) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setBypassLocalNetwork(bypass) }
    }

    fun setBypassOffice365(bypass: Boolean) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setBypassOffice365(bypass) }
    }

    fun setMetered(metered: Boolean) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setMetered(metered) }
    }

    fun setDnsMode(mode: DnsMode) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setDnsMode(mode) }
    }

    fun setDohUrl(url: String) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setDohUrl(url) }
    }

    fun setDoqUrl(url: String) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setDoqUrl(url) }
    }

    fun setCustomSni(sni: String) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setCustomSni(sni) }
    }

    fun setConnectUri(uri: String) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setConnectUri(uri) }
    }

    fun setUseHttp2(enabled: Boolean) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setUseHttp2(enabled) }
    }

    fun setAutoConnect(enabled: Boolean) {
        viewModelScope.launch { prefs.setAutoConnect(enabled) }
    }

    fun setThemeMode(mode: ThemeMode) {
        viewModelScope.launch { prefs.setThemeMode(mode) }
    }
}
