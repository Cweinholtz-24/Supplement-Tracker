
//
//  ProtocolDetailView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct ProtocolDetailView: View {
    @EnvironmentObject var apiService: APIService
    let protocolItem: ProtocolModel
    
    @State private var compoundStates: [String: Bool] = [:]
    @State private var compoundNotes: [String: String] = [:]
    @State private var isLoading = false
    @State private var showingSuccess = false
    @State private var showingError = false
    @State private var errorMessage = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Protocol Header
                VStack(alignment: .leading, spacing: 8) {
                    Text(protocolItem.name)
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    
                    Text("Frequency: \(protocolItem.frequency)")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    
                    if !protocolItem.description.isEmpty {
                        Text(protocolItem.description)
                            .font(.body)
                            .foregroundColor(.secondary)
                    }
                }
                .padding()
                .background(Color.gray.opacity(0.1))
                .cornerRadius(12)
                
                // Compounds Section
                VStack(alignment: .leading, spacing: 16) {
                    Text("Today's Compounds")
                        .font(.title2)
                        .fontWeight(.semibold)
                    
                    ForEach(protocolItem.compounds, id: \.self) { compound in
                        CompoundRowView(
                            compound: compound,
                            isChecked: compoundStates[compound] ?? false,
                            note: compoundNotes[compound] ?? "",
                            onToggle: { isChecked in
                                compoundStates[compound] = isChecked
                            },
                            onNoteChanged: { note in
                                compoundNotes[compound] = note
                            }
                        )
                    }
                }
                .padding()
                .background(Color.gray.opacity(0.05))
                .cornerRadius(12)
                
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
                .padding()
            }
        }
        .navigationTitle("Protocol Details")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Success", isPresented: $showingSuccess) {
            Button("OK") { }
        } message: {
            Text("Log saved successfully!")
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
        .onAppear {
            initializeStates()
        }
    }
    
    private func initializeStates() {
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
        
        apiService.saveProtocolLog(
            protocolId: protocolItem.id,
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
    let isChecked: Bool
    let note: String
    let onToggle: (Bool) -> Void
    let onNoteChanged: (String) -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button(action: {
                    onToggle(!isChecked)
                }) {
                    Image(systemName: isChecked ? "checkmark.circle.fill" : "circle")
                        .font(.title2)
                        .foregroundColor(isChecked ? .green : .gray)
                }
                
                Text(compound)
                    .font(.body)
                    .fontWeight(.medium)
                    .strikethrough(isChecked)
                
                Spacer()
            }
            
            TextField("Notes (optional)", text: Binding(
                get: { note },
                set: { onNoteChanged($0) }
            ))
            .textFieldStyle(RoundedBorderTextFieldStyle())
            .font(.caption)
        }
        .padding(.vertical, 4)
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
