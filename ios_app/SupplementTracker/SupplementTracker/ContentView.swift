
//
//  ContentView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var apiService = APIService.shared
    
    var body: some View {
        Group {
            if apiService.isAuthenticated {
                DashboardView()
                    .environmentObject(apiService)
            } else {
                LoginView()
                    .environmentObject(apiService)
            }
        }
        .onAppear {
            // Check if user is already authenticated
            if apiService.authToken != nil {
                apiService.isAuthenticated = true
            }
        }
    }
}

#Preview {
    ContentView()
}
