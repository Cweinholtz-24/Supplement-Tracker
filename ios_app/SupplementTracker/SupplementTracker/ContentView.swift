
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
            LoginView()
                .environmentObject(apiService)
        }
    }
}

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

struct ProtocolDetailView: View {
    let protocol: ProtocolModel
    @State private var todayLog: [String: Bool] = [:]
    @State private var notes: [String: String] = [:]
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Today's Tracking")
                .font(.title2)
                .fontWeight(.semibold)
            
            VStack(spacing: 12) {
                ForEach(protocol.compounds, id: \.self) { compound in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(compound)
                                .font(.headline)
                            TextField("Add notes...", text: Binding(
                                get: { notes[compound] ?? "" },
                                set: { notes[compound] = $0 }
                            ))
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .font(.caption)
                        }
                        
                        Spacer()
                        
                        Button(action: {
                            todayLog[compound] = !(todayLog[compound] ?? false)
                        }) {
                            Image(systemName: todayLog[compound] ?? false ? "checkmark.circle.fill" : "circle")
                                .font(.title2)
                                .foregroundColor(todayLog[compound] ?? false ? .green : .gray)
                        }
                    }
                    .padding()
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(10)
                }
            }
            
            Button(action: {
                // Save today's log
                saveLog()
            }) {
                Text("Save Today's Log")
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(10)
            }
            
            Spacer()
        }
        .padding()
        .navigationTitle(protocol.name)
        .navigationBarTitleDisplayMode(.inline)
    }
    
    private func saveLog() {
        // Here you would call your webapp API to save the log
        print("Saving log for \(protocol.name)")
        print("Taken: \(todayLog)")
        print("Notes: \(notes)")
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
