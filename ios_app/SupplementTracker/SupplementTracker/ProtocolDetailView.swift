
//
//  ProtocolDetailView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct ProtocolDetailView: View {
    let protocolItem: ProtocolModel
    @EnvironmentObject var apiService: APIService
    @State private var compoundStates: [String: Bool] = [:]
    @State private var compoundNotes: [String: String] = [:]
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingError = false
    @State private var successMessage = ""
    @State private var showingSuccess = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Protocol Header
                VStack(alignment: .leading, spacing: 8) {
                    Text(protocolItem.name)
                        .font(.title)
                        .fontWeight(.bold)
                    
                    Text(protocolItem.description)
                        .font(.body)
                        .foregroundColor(.secondary)
                    
                    Text("\(protocolItem.compounds.count) compounds • \(protocolItem.frequency)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal)

                // Compounds Section
                VStack(alignment: .leading, spacing: 16) {
                    Text("Today's Tracking")
                        .font(.headline)
                        .fontWeight(.semibold)
                        .padding(.horizontal)
                    
                    ForEach(protocolItem.compounds, id: \.self) { compound in
                        CompoundRowView(
                            compound: compound,
                            taken: Binding(
                                get: { compoundStates[compound] ?? false },
                                set: { compoundStates[compound] = $0 }
                            ),
                            note: Binding(
                                get: { compoundNotes[compound] ?? "" },
                                set: { compoundNotes[compound] = $0 }
                            )
                        )
                        .padding(.horizontal)
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
                    .cornerRadius(10)
                }
                .disabled(isLoading)
                .padding(.horizontal)
                .padding(.top, 20)
            }
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
            Text(successMessage)
        }
        .onAppear {
            initializeStates()
        }
    }
    
    private func initializeStates() {
        // Initialize compound states
        for compound in protocolItem.compounds {
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
        
        let protocolId = protocolItem.id
        
        apiService.saveProtocolLog(
            protocolId: protocolId,
            compounds: compoundStates,
            notes: compoundNotes
        ) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    successMessage = "Log saved successfully!"
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
    @Binding var taken: Bool
    @Binding var note: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button(action: { taken.toggle() }) {
                    HStack {
                        Image(systemName: taken ? "checkmark.circle.fill" : "circle")
                            .foregroundColor(taken ? .green : .gray)
                            .font(.title2)
                        
                        Text(compound)
                            .font(.body)
                            .fontWeight(.medium)
                            .foregroundColor(.primary)
                        
                        Spacer()
                    }
                }
                .buttonStyle(PlainButtonStyle())
            }
            
            TextField("Add notes...", text: $note)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .font(.caption)
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(10)
    }
}

struct ProtocolRowView: View {
    let protocolItem: ProtocolModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(protocolItem.name)
                .font(.headline)
                .fontWeight(.semibold)
            
            Text("\(protocolItem.compounds.count) compounds • \(protocolItem.frequency)")
                .font(.caption)
                .foregroundColor(.secondary)
            
            if !protocolItem.description.isEmpty {
                Text(protocolItem.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    NavigationView {
        ProtocolDetailView(protocolItem: ProtocolModel(
            id: "1",
            name: "Morning Stack",
            compounds: ["Vitamin D", "Omega-3", "Magnesium"],
            frequency: "Daily",
            description: "Essential morning supplements"
        ))
    }
    .environmentObject(APIService.shared)
}
