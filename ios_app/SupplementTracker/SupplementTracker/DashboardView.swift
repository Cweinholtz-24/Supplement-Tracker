
//
//  DashboardView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var apiService: APIService
    @State private var protocols: [ProtocolModel] = []
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingError = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if isLoading {
                    ProgressView("Loading protocols...")
                        .progressViewStyle(CircularProgressViewStyle())
                } else if protocols.isEmpty {
                    VStack(spacing: 16) {
                        Image(systemName: "pills.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.gray)
                        
                        Text("No Protocols Yet")
                            .font(.title2)
                            .fontWeight(.semibold)
                        
                        Text("Create your first supplement protocol to start tracking")
                            .font(.body)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }
                    .padding(.top, 60)
                } else {
                    List(protocols) { protocolItem in
                        NavigationLink(destination: ProtocolDetailView(protocolItem: protocolItem)) {
                            ProtocolRowView(protocolItem: protocolItem)
                        }
                    }
                }
                
                Spacer()
            }
            .navigationTitle("My Protocols")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Logout") {
                        apiService.logout()
                    }
                    .foregroundColor(.red)
                }
            }
            .alert("Error", isPresented: $showingError) {
                Button("OK") { }
            } message: {
                Text(errorMessage)
            }
        }
        .onAppear {
            loadProtocols()
        }
    }
    
    private func loadProtocols() {
        isLoading = true
        apiService.fetchProtocols { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success(let fetchedProtocols):
                    protocols = fetchedProtocols
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    showingError = true
                }
            }
        }
    }
}

#Preview {
    DashboardView()
        .environmentObject(APIService.shared)
}
