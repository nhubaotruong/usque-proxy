package com.nhubaotruong.usqueproxy.ui.nav

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import com.nhubaotruong.usqueproxy.ui.screen.MainScreen
import com.nhubaotruong.usqueproxy.ui.screen.SettingsScreen
import com.nhubaotruong.usqueproxy.ui.screen.SplitTunnelScreen
import com.nhubaotruong.usqueproxy.ui.viewmodel.VpnViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private data class NavItem(val label: String, val icon: ImageVector)

private val navItems = listOf(
    NavItem("Home", Icons.Default.Home),
    NavItem("Split Tunnel", Icons.Default.FilterList),
    NavItem("Settings", Icons.Default.Settings),
)

@Composable
fun AppNavigation(
    viewModel: VpnViewModel,
    onRequestVpnPermission: () -> Unit,
) {
    val pagerState = rememberPagerState(pageCount = { navItems.size })
    val scope = rememberCoroutineScope()

    // Lightweight state poll — reads volatile booleans only, no JNI.
    // Paused when app goes to background via repeatOnLifecycle(STARTED).
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                viewModel.refreshState()
                delay(VpnViewModel.STATE_POLL_INTERVAL)
            }
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                navItems.forEachIndexed { index, item ->
                    NavigationBarItem(
                        selected = pagerState.currentPage == index,
                        onClick = { scope.launch { pagerState.animateScrollToPage(index) } },
                        icon = { Icon(item.icon, contentDescription = item.label) },
                        label = { Text(item.label) },
                    )
                }
            }
        }
    ) { padding ->
        HorizontalPager(
            state = pagerState,
            modifier = Modifier.padding(padding),
        ) { page ->
            when (page) {
                0 -> MainScreen(
                    viewModel = viewModel,
                    onRequestVpnPermission = onRequestVpnPermission,
                )
                1 -> SplitTunnelScreen(viewModel = viewModel)
                2 -> SettingsScreen(viewModel = viewModel)
            }
        }
    }
}
