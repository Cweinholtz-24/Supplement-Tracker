
//
//  ProtocolDetailView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct ProtocolDetailView: View {
    let protocol: ProtocolModel
    @EnvironmentObject var apiService: APIService
    @State private var compoundStates: [String: Bool] = [:]
    @State private var compoundNotes: [String: String] = [:]
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingError = false
    @State private var showingSuccess = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Protocol Info
                VStack(alignment: .leading, spacing: 12) {
                    Text(protocol.name)
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    
                    Text("Frequency: \(protocol.frequency)")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    
                    if !protocol.description.isEmpty {
                        Text(protocol.description)
                            .font(.body)
                            .foregroundColor(.secondary)
                    }
                }
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(12)
                
                // Compounds Section
                VStack(alignment: .leading, spacing: 16) {
                    Text("Today's Compounds")
                        .font(.title2)
                        .fontWeight(.semibold)
                    
                    ForEach(protocol.compounds, id: \.self) { compound in
                        CompoundRowView(
                            compound: compound,
                            isTaken: Binding(
                                get: { compoundStates[compound] ?? false },
                                set: { compoundStates[compound] = $0 }
                            ),
                            note: Binding(
                                get: { compoundNotes[compound] ?? "" },
                                set: { compoundNotes[compound] = $0 }
                            )
                        )
                    }
                }
                
                // Save Button
                Button(action: saveLog) {
                    HStack {
                        if isLoading {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                .scaleEffect(0.8)
                        }
                        Text(isLoading ? "Saving..." : "Save Today's Log")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
                }
                .disabled(isLoading)
                .padding(.top)
            }
            .padding()
        }
        .navigationTitle("Protocol Details")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
        .alert("Success", isPresented: $showingSuccess) {
            Button("OK") { }
        } message: {
            Text("Log saved successfully!")
        }
        .onAppear {
            initializeStates()
        }
    }
    
    private func initializeStates() {
        for compound in protocol.compounds {
            if compoundStates[compound] == nil {
                compoundStates[compound] = false
            }
            if compoundNotes[compound] == nil {
                compoundNotes[compound] = ""
            }
        }
    }
    
    private func saveLog() {
        isLoading = true
        
        apiService.saveProtocolLog(
            protocolId: protocol.id,
            compounds: compoundStates,
            notes: compoundNotes
        ) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    showingSuccess = true
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    showingError = true
                }
            }
        }
    }
}

struct CompoundRowView: View {
    let compound: String
    @Binding var isTaken: Bool
    @Binding var note: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button(action: { isTaken.toggle() }) {
                    Image(systemName: isTaken ? "checkmark.circle.fill" : "circle")
                        .font(.title2)
                        .foregroundColor(isTaken ? .green : .gray)
                }
                
                Text(compound)
                    .font(.headline)
                    .strikethrough(isTaken)
                    .foregroundColor(isTaken ? .secondary : .primary)
                
                Spacer()
            }
            
            TextField("Add notes (optional)", text: $note)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .font(.body)
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

#Preview {
    NavigationView {
        ProtocolDetailView(protocol: ProtocolModel(
            id: "test",
            name: "Test Protocol",
            compounds: ["FOXO4-DRI", "Fisetin", "Quercetin"],
            frequency: "Daily",
            description: "Test description"
        ))
        .environmentObject(APIService.shared)
    }
}
