package com.nhubaotruong.usqueproxy.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

enum class SplitMode { ALL, INCLUDE, EXCLUDE }
enum class ThemeMode { SYSTEM, LIGHT, DARK }
enum class DnsMode { SYSTEM, CLOUDFLARE, CUSTOM_DOH }
enum class ProfileType { WARP, ZERO_TRUST }

data class VpnPrefs(
    val splitMode: SplitMode = SplitMode.ALL,
    val includedApps: Set<String> = emptySet(),
    val excludedApps: Set<String> = emptySet(),
    val bypassLocalNetwork: Boolean = true,
    val bypassOffice365: Boolean = false,
    val isMetered: Boolean = false,
    val dnsMode: DnsMode = DnsMode.SYSTEM,
    val dohUrl: String = "",
    val activeProfile: ProfileType = ProfileType.WARP,
    val warpConfigJson: String = "",
    val isWarpRegistered: Boolean = false,
    val ztConfigJson: String = "",
    val isZtRegistered: Boolean = false,
    val customSni: String = "",
    val connectUri: String = "",
    val autoConnect: Boolean = false,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
) {
    val activeConfigJson: String
        get() = when (activeProfile) {
            ProfileType.WARP -> warpConfigJson
            ProfileType.ZERO_TRUST -> ztConfigJson
        }

    val isActiveRegistered: Boolean
        get() = when (activeProfile) {
            ProfileType.WARP -> isWarpRegistered
            ProfileType.ZERO_TRUST -> isZtRegistered
        }
}

private val Context.dataStore by preferencesDataStore(name = "vpn_prefs")

class VpnPreferences(private val context: Context) {

    private object Keys {
        val SPLIT_MODE = stringPreferencesKey("split_mode")
        val SELECTED_APPS = stringSetPreferencesKey("selected_apps") // legacy, for migration
        val INCLUDED_APPS = stringSetPreferencesKey("included_apps")
        val EXCLUDED_APPS = stringSetPreferencesKey("excluded_apps")
        val BYPASS_LOCAL = booleanPreferencesKey("bypass_local")
        val BYPASS_OFFICE365 = booleanPreferencesKey("bypass_office365")
        val IS_METERED = booleanPreferencesKey("is_metered")
        val USE_SYSTEM_DNS = booleanPreferencesKey("use_system_dns") // legacy, for migration
        val DNS_MODE = stringPreferencesKey("dns_mode")
        val DOH_URL = stringPreferencesKey("doh_url")
        // Legacy keys (migrated to per-profile)
        val CONFIG_JSON = stringPreferencesKey("config_json")
        val IS_REGISTERED = booleanPreferencesKey("is_registered")
        // Per-profile keys
        val ACTIVE_PROFILE = stringPreferencesKey("active_profile")
        val WARP_CONFIG_JSON = stringPreferencesKey("warp_config_json")
        val IS_WARP_REGISTERED = booleanPreferencesKey("is_warp_registered")
        val ZT_CONFIG_JSON = stringPreferencesKey("zt_config_json")
        val IS_ZT_REGISTERED = booleanPreferencesKey("is_zt_registered")
        val CUSTOM_SNI = stringPreferencesKey("custom_sni")
        val CONNECT_URI = stringPreferencesKey("connect_uri")
        val AUTO_CONNECT = booleanPreferencesKey("auto_connect")
        val THEME_MODE = stringPreferencesKey("theme_mode")
    }

    val prefsFlow: Flow<VpnPrefs> = context.dataStore.data.map { p ->
        // Migration: old config_json/is_registered → warp_config_json/is_warp_registered
        val warpConfig = p[Keys.WARP_CONFIG_JSON]
            ?: p[Keys.CONFIG_JSON] ?: ""
        val isWarpReg = p[Keys.IS_WARP_REGISTERED]
            ?: p[Keys.IS_REGISTERED] ?: false

        VpnPrefs(
            splitMode = runCatching { SplitMode.valueOf(p[Keys.SPLIT_MODE] ?: "ALL") }
                .getOrDefault(SplitMode.ALL),
            includedApps = p[Keys.INCLUDED_APPS]
                ?: p[Keys.SELECTED_APPS] ?: emptySet(),
            excludedApps = p[Keys.EXCLUDED_APPS] ?: emptySet(),
            bypassLocalNetwork = p[Keys.BYPASS_LOCAL] ?: true,
            bypassOffice365 = p[Keys.BYPASS_OFFICE365] ?: false,
            isMetered = p[Keys.IS_METERED] ?: false,
            dnsMode = p[Keys.DNS_MODE]?.let {
                runCatching { DnsMode.valueOf(it) }.getOrDefault(DnsMode.CLOUDFLARE)
            } ?: run {
                // Migration: map old USE_SYSTEM_DNS to DnsMode
                val useSystem = p[Keys.USE_SYSTEM_DNS] ?: true
                if (useSystem) DnsMode.SYSTEM else DnsMode.CLOUDFLARE
            },
            dohUrl = p[Keys.DOH_URL] ?: "",
            activeProfile = runCatching {
                ProfileType.valueOf(p[Keys.ACTIVE_PROFILE] ?: "WARP")
            }.getOrDefault(ProfileType.WARP),
            warpConfigJson = warpConfig,
            isWarpRegistered = isWarpReg,
            ztConfigJson = p[Keys.ZT_CONFIG_JSON] ?: "",
            isZtRegistered = p[Keys.IS_ZT_REGISTERED] ?: false,
            autoConnect = p[Keys.AUTO_CONNECT] ?: false,
            customSni = p[Keys.CUSTOM_SNI] ?: "",
            connectUri = p[Keys.CONNECT_URI] ?: "",
            themeMode = runCatching { ThemeMode.valueOf(p[Keys.THEME_MODE] ?: "SYSTEM") }
                .getOrDefault(ThemeMode.SYSTEM),
        )
    }

    suspend fun setSplitMode(mode: SplitMode) {
        context.dataStore.edit { it[Keys.SPLIT_MODE] = mode.name }
    }

    suspend fun setIncludedApps(apps: Set<String>) {
        context.dataStore.edit { it[Keys.INCLUDED_APPS] = apps }
    }

    suspend fun setExcludedApps(apps: Set<String>) {
        context.dataStore.edit { it[Keys.EXCLUDED_APPS] = apps }
    }

    suspend fun setBypassLocalNetwork(bypass: Boolean) {
        context.dataStore.edit { it[Keys.BYPASS_LOCAL] = bypass }
    }

    suspend fun setBypassOffice365(bypass: Boolean) {
        context.dataStore.edit { it[Keys.BYPASS_OFFICE365] = bypass }
    }

    suspend fun setMetered(metered: Boolean) {
        context.dataStore.edit { it[Keys.IS_METERED] = metered }
    }

    suspend fun setDnsMode(mode: DnsMode) {
        context.dataStore.edit { it[Keys.DNS_MODE] = mode.name }
    }

    suspend fun setDohUrl(url: String) {
        context.dataStore.edit { it[Keys.DOH_URL] = url }
    }

    suspend fun saveWarpConfig(json: String) {
        context.dataStore.edit {
            it[Keys.WARP_CONFIG_JSON] = json
            it[Keys.IS_WARP_REGISTERED] = true
        }
    }

    suspend fun saveZtConfig(json: String) {
        context.dataStore.edit {
            it[Keys.ZT_CONFIG_JSON] = json
            it[Keys.IS_ZT_REGISTERED] = true
        }
    }

    suspend fun clearWarpConfig() {
        context.dataStore.edit {
            it[Keys.WARP_CONFIG_JSON] = ""
            it[Keys.IS_WARP_REGISTERED] = false
        }
    }

    suspend fun clearZtConfig() {
        context.dataStore.edit {
            it[Keys.ZT_CONFIG_JSON] = ""
            it[Keys.IS_ZT_REGISTERED] = false
        }
    }

    suspend fun setActiveProfile(profile: ProfileType) {
        context.dataStore.edit { it[Keys.ACTIVE_PROFILE] = profile.name }
    }

    suspend fun setCustomSni(sni: String) {
        context.dataStore.edit { it[Keys.CUSTOM_SNI] = sni }
    }

    suspend fun setConnectUri(uri: String) {
        context.dataStore.edit { it[Keys.CONNECT_URI] = uri }
    }

    suspend fun setAutoConnect(enabled: Boolean) {
        context.dataStore.edit { it[Keys.AUTO_CONNECT] = enabled }
    }

    suspend fun setThemeMode(mode: ThemeMode) {
        context.dataStore.edit { it[Keys.THEME_MODE] = mode.name }
    }
}
