
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
                    List(protocols) { protocolItem in
                        NavigationLink(destination: ProtocolDetailView(protocolModel: protocolItem)) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(protocolItem.name)
                                    .font(.headline)
                                Text("\(protocolItem.compounds.count) compounds")
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
        
        apiService.fetchProtocols { result in
            DispatchQueue.main.async {
                self.isLoading = false
                switch result {
                case .success(let fetchedProtocols):
                    self.protocols = fetchedProtocols
                case .failure(let error):
                    self.errorMessage = "Failed to load protocols: \(error.localizedDescription)"
                    self.protocols = []
                }
            }
        }
    }
}
