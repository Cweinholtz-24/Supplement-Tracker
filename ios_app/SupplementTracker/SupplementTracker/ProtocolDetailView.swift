
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
    @Environment(\.dismiss) private var dismiss
    
    @State private var compoundStates: [String: Bool] = [:]
    @State private var compoundNotes: [String: String] = [:]
    @State private var generalNote = ""
    @State private var isLoading = false
    @State private var showingSuccess = false
    @State private var errorMessage = ""
    @State private var showingError = false
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    // Protocol Header
                    VStack(alignment: .leading, spacing: 8) {
                        Text(protocolItem.name)
                            .font(.largeTitle)
                            .fontWeight(.bold)
                        
                        if !protocolItem.displayDescription.isEmpty {
                            Text(protocolItem.displayDescription)
                                .font(.body)
                                .foregroundColor(.secondary)
                        }
                        
                        Text("Frequency: \(protocolItem.displayFrequency)")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    
                    // Compounds Section
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Today's Log")
                            .font(.title2)
                            .fontWeight(.semibold)
                        
                        ForEach(protocolItem.compounds, id: \.self) { compound in
                            CompoundLogView(
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
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    
                    // General Notes
                    VStack(alignment: .leading, spacing: 12) {
                        Text("General Notes")
                            .font(.title3)
                            .fontWeight(.semibold)
                        
                        TextField("How are you feeling today?", text: $generalNote, axis: .vertical)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .lineLimit(3...6)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    
                    // Save Button
                    Button(action: saveLog) {
                        HStack {
                            if isLoading {
                                ProgressView()
                                    .scaleEffect(0.8)
                                    .foregroundColor(.white)
                            }
                            Text(isLoading ? "Saving..." : "Save Today's Log")
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(hasAnyData ? Color.blue : Color.gray)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                    }
                    .disabled(isLoading || !hasAnyData)
                }
                .padding()
            }
            .navigationTitle("Protocol Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .onAppear {
            initializeStates()
        }
        .alert("Success", isPresented: $showingSuccess) {
            Button("OK") {
                dismiss()
            }
        } message: {
            Text("Your log has been saved successfully!")
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
    }
    
    private var hasAnyData: Bool {
        compoundStates.values.contains(true) || !generalNote.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
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
        
        // Prepare notes dictionary
        var allNotes = compoundNotes
        if !generalNote.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            allNotes["general"] = generalNote
        }
        
        apiService.saveProtocolLog(protocolId: protocolItem.id, compounds: compoundStates, notes: allNotes) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    // Log taken supplements to HealthKit
                    for (compound, isTaken) in compoundStates where isTaken {
                        HealthKitManager.shared.logSupplement(name: compound, amount: 1, unit: "count")
                    }
                    showingSuccess = true
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    showingError = true
                }
            }
        }
    }
}

struct CompoundLogView: View {
    let compound: String
    @Binding var isTaken: Bool
    @Binding var note: String
    @State private var showingNoteField = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button(action: { isTaken.toggle() }) {
                    Image(systemName: isTaken ? "checkmark.circle.fill" : "circle")
                        .font(.title2)
                        .foregroundColor(isTaken ? .green : .gray)
                }
                
                Text(compound)
                    .font(.body)
                    .fontWeight(.medium)
                    .strikethrough(isTaken)
                
                Spacer()
                
                Button(action: { showingNoteField.toggle() }) {
                    Image(systemName: "note.text")
                        .font(.subheadline)
                        .foregroundColor(.blue)
                }
            }
            
            if showingNoteField {
                TextField("Add a note...", text: $note)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .font(.caption)
            }
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    NavigationStack {
        ProtocolDetailView(protocolItem: ProtocolModel(
            id: "1",
            name: "Morning Stack",
            compounds: ["Vitamin D", "Omega-3", "Magnesium"],
            description: "Daily morning supplements"
        ))
    }
    .environmentObject(APIService.shared)
}
