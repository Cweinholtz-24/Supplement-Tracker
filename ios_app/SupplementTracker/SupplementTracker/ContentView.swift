
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
    @State private var isLoggedIn = false

    var body: some View {
        if apiService.isAuthenticated || isLoggedIn {
            DashboardView()
                .environmentObject(apiService)
        } else {
            LoginView(isLoggedIn: $isLoggedIn)
                .environmentObject(apiService)
        }
    }
    .onReceive(apiService.$isAuthenticated) { authenticated in
        if !authenticated {
            isLoggedIn = false
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
