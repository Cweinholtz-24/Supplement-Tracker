
//
//  DashboardView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI
import Foundation

struct DashboardView: View {
    @EnvironmentObject var apiService: APIService
    @State private var protocols: [ProtocolModel] = []
    @State private var isLoading = false
    @State private var errorMessage = ""
    
    var body: some View {
        NavigationView {
            VStack {
                if isLoading {
                    ProgressView("Loading protocols...")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if protocols.isEmpty {
                    VStack(spacing: 20) {
                        Image(systemName: "pills.circle")
                            .font(.system(size: 60))
                            .foregroundColor(.blue)
                        Text("No protocols yet")
                            .font(.title2)
                            .foregroundColor(.secondary)
                        Text("Create your first supplement protocol to get started!")
                            .multilineTextAlignment(.center)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(protocols) { protocol in
                        NavigationLink(destination: ProtocolDetailView(protocol: protocol)) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(protocol.name)
                                    .font(.headline)
                                Text("\(protocol.compounds.count) compounds")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
                
                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .foregroundColor(.red)
                        .padding()
                }
            }
            .navigationTitle("💊 Supplement Tracker")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Logout") {
                        apiService.logout()
                    }
                }
            }
        }
        .onAppear {
            loadProtocols()
        }
    }
    
    private func loadProtocols() {
        isLoading = true
        errorMessage = ""
        
        // This would call your webapp API
        // For now, we'll add some dummy data
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            self.protocols = [
                ProtocolModel(id: "1", name: "Senolytic Stack", compounds: ["FOXO4-DRI", "Fisetin", "Quercetin"]),
                ProtocolModel(id: "2", name: "Longevity Protocol", compounds: ["NMN", "Resveratrol", "Metformin"])
            ]
            self.isLoading = false
        }
    }
}
