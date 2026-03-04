package com.nhubaotruong.usqueproxy

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import com.nhubaotruong.usqueproxy.data.ThemeMode
import com.nhubaotruong.usqueproxy.ui.nav.AppNavigation
import com.nhubaotruong.usqueproxy.ui.theme.UsqueProxyTheme
import com.nhubaotruong.usqueproxy.ui.viewmodel.VpnViewModel

class MainActivity : ComponentActivity() {

    companion object {
        const val ACTION_CONNECT_VPN = "com.nhubaotruong.usqueproxy.CONNECT_VPN"
    }

    private val vpnViewModel: VpnViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            vpnViewModel.connect()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val prefs by vpnViewModel.vpnPrefs.collectAsState()
            val darkTheme = when (prefs.themeMode) {
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
            }
            UsqueProxyTheme(darkTheme = darkTheme) {
                AppNavigation(
                    viewModel = vpnViewModel,
                    onRequestVpnPermission = { requestVpnPermission() },
                )
            }
        }
        handleConnectAction(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleConnectAction(intent)
    }

    private fun handleConnectAction(intent: Intent?) {
        if (intent?.action == ACTION_CONNECT_VPN) {
            requestVpnPermission()
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            // Permission already granted
            vpnViewModel.connect()
        }
    }
}
