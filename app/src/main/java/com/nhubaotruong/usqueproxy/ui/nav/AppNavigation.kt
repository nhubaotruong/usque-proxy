package com.nhubaotruong.usqueproxy.ui.nav

import androidx.compose.animation.core.tween
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.nhubaotruong.usqueproxy.ui.screen.MainScreen
import com.nhubaotruong.usqueproxy.ui.screen.SettingsScreen
import com.nhubaotruong.usqueproxy.ui.viewmodel.VpnViewModel

private const val ANIM_DURATION = 300

@Composable
fun AppNavigation(
    viewModel: VpnViewModel,
    onRequestVpnPermission: () -> Unit,
) {
    val navController = rememberNavController()

    NavHost(
        navController = navController,
        startDestination = "main",
        enterTransition = { slideInHorizontally(tween(ANIM_DURATION)) { it } },
        exitTransition = { slideOutHorizontally(tween(ANIM_DURATION)) { -it } },
        popEnterTransition = { slideInHorizontally(tween(ANIM_DURATION)) { -it } },
        popExitTransition = { slideOutHorizontally(tween(ANIM_DURATION)) { it } },
    ) {
        composable("main") {
            MainScreen(
                viewModel = viewModel,
                onNavigateToSettings = { navController.navigate("settings") },
                onRequestVpnPermission = onRequestVpnPermission,
            )
        }
        composable("settings") {
            SettingsScreen(
                viewModel = viewModel,
                onNavigateBack = { navController.popBackStack() },
            )
        }
    }
}
