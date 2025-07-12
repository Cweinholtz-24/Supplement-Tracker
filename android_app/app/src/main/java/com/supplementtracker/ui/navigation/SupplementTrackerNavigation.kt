
package com.supplementtracker.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.supplementtracker.ui.auth.LoginScreen
import com.supplementtracker.ui.auth.LoginViewModel
import com.supplementtracker.ui.dashboard.DashboardScreen
import com.supplementtracker.ui.protocol.ProtocolDetailScreen
import com.supplementtracker.ui.protocol.CreateProtocolScreen
import com.supplementtracker.ui.analytics.AnalyticsScreen
import com.supplementtracker.ui.settings.SettingsScreen

@Composable
fun SupplementTrackerNavigation(
    navController: NavHostController
) {
    val loginViewModel: LoginViewModel = hiltViewModel()
    val isLoggedIn by loginViewModel.isLoggedIn.collectAsState()
    
    val startDestination = if (isLoggedIn) "dashboard" else "login"
    
    NavHost(
        navController = navController,
        startDestination = startDestination
    ) {
        composable("login") {
            LoginScreen(
                onLoginSuccess = {
                    navController.navigate("dashboard") {
                        popUpTo("login") { inclusive = true }
                    }
                }
            )
        }
        
        composable("dashboard") {
            DashboardScreen(
                onProtocolClick = { protocolId ->
                    navController.navigate("protocol_detail/$protocolId")
                },
                onCreateProtocolClick = {
                    navController.navigate("create_protocol")
                },
                onSettingsClick = {
                    navController.navigate("settings")
                },
                onLogout = {
                    navController.navigate("login") {
                        popUpTo("dashboard") { inclusive = true }
                    }
                }
            )
        }
        
        composable("protocol_detail/{protocolId}") { backStackEntry ->
            val protocolId = backStackEntry.arguments?.getString("protocolId") ?: ""
            ProtocolDetailScreen(
                protocolId = protocolId,
                onBackClick = { navController.popBackStack() },
                onAnalyticsClick = { 
                    navController.navigate("analytics/$protocolId")
                }
            )
        }
        
        composable("create_protocol") {
            CreateProtocolScreen(
                onProtocolCreated = { navController.popBackStack() },
                onBackClick = { navController.popBackStack() }
            )
        }
        
        composable("analytics/{protocolId}") { backStackEntry ->
            val protocolId = backStackEntry.arguments?.getString("protocolId") ?: ""
            AnalyticsScreen(
                protocolId = protocolId,
                onBackClick = { navController.popBackStack() }
            )
        }
        
        composable("settings") {
            SettingsScreen(
                onBackClick = { navController.popBackStack() }
            )
        }
    }
}
