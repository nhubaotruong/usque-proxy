package com.nhubaotruong.usqueproxy.ui.viewmodel

import android.app.Application
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import com.nhubaotruong.usqueproxy.data.AppInfo
import com.nhubaotruong.usqueproxy.data.AppRepository
import com.nhubaotruong.usqueproxy.data.DnsMode
import com.nhubaotruong.usqueproxy.data.ProfileType
import com.nhubaotruong.usqueproxy.data.SplitMode
import com.nhubaotruong.usqueproxy.data.ThemeMode
import com.nhubaotruong.usqueproxy.data.VpnPreferences
import com.nhubaotruong.usqueproxy.data.VpnPrefs
import com.nhubaotruong.usqueproxy.vpn.UsqueVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import usquebind.Usquebind

enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED }

data class TunnelStats(
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
)

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = VpnPreferences(application)
    private val appRepo = AppRepository(application)

    val vpnPrefs: StateFlow<VpnPrefs> = prefs.prefsFlow
        .stateIn(viewModelScope, SharingStarted.Eagerly, VpnPrefs())

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
    fun clearTunnelError() { _tunnelError.value = null }

    companion object {
        private const val POLL_INTERVAL_FOREGROUND = 1_000L // 1s when visible
    }

    private var pollJob: Job? = null

    private val lifecycleObserver = object : DefaultLifecycleObserver {
        override fun onStart(owner: LifecycleOwner) = startPolling()
        override fun onStop(owner: LifecycleOwner) = stopPolling()
    }

    init {
        ProcessLifecycleOwner.get().lifecycle.addObserver(lifecycleObserver)
        startPolling()
    }

    private fun startPolling() {
        if (pollJob?.isActive == true) return
        pollJob = viewModelScope.launch {
            while (true) {
                val running = UsqueVpnService.isRunning
                _vpnState.value = if (running) VpnState.CONNECTED else VpnState.DISCONNECTED
                if (!running) _needsRestart.value = false

                val error = UsqueVpnService.lastError
                if (error != null) { _tunnelError.value = error; UsqueVpnService.clearError() }

                if (running) {
                    runCatching {
                        val json = withContext(Dispatchers.IO) {
                            JSONObject(Usquebind.getStats())
                        }
                        _stats.value = TunnelStats(
                            txBytes = json.optLong("tx_bytes", 0L),
                            rxBytes = json.optLong("rx_bytes", 0L),
                        )
                        if (_connectedSince.value == null) {
                            val uptimeSec = json.optInt("uptime_sec", 0)
                            _connectedSince.value = System.currentTimeMillis() - uptimeSec * 1000L
                        }
                    }
                } else {
                    _connectedSince.value = null
                }
                delay(POLL_INTERVAL_FOREGROUND)
            }
        }
    }

    private fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    override fun onCleared() {
        ProcessLifecycleOwner.get().lifecycle.removeObserver(lifecycleObserver)
        super.onCleared()
    }

    fun connect() {
        if (_vpnState.value != VpnState.DISCONNECTED) return
        _vpnState.value = VpnState.CONNECTING
        UsqueVpnService.clearError()

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
        disconnect()
        _needsRestart.value = false
        // Small delay to let the service stop before reconnecting
        viewModelScope.launch {
            delay(500)
            connect()
        }
    }

    private fun markRestartNeeded() {
        if (UsqueVpnService.isRunning) {
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

    fun setPreventDnsLeak(prevent: Boolean) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setPreventDnsLeak(prevent) }
    }

    fun setCustomSni(sni: String) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setCustomSni(sni) }
    }

    fun setConnectUri(uri: String) {
        markRestartNeeded()
        viewModelScope.launch { prefs.setConnectUri(uri) }
    }

    fun setThemeMode(mode: ThemeMode) {
        viewModelScope.launch { prefs.setThemeMode(mode) }
    }
}
