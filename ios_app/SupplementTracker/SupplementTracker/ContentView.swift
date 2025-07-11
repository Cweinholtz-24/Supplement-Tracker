//
//  ContentView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI
import Foundation

struct ContentView: View {
    @StateObject private var apiService = APIService()

    var body: some View {
        if apiService.isAuthenticated {
            DashboardView()
                .environmentObject(apiService)
        } else {
            LoginView(isLoggedIn: .constant(false))
                .environmentObject(apiService)
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}