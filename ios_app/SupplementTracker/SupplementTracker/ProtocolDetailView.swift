
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
    @State private var isSaving = false
    @State private var showingSaveSuccess = false
    @State private var errorMessage = ""
    @State private var showingError = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Protocol Header
                VStack(alignment: .leading, spacing: 8) {
                    Text(protocol.name)
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    
                    if !protocol.description.isEmpty {
                        Text(protocol.description)
                            .font(.body)
                            .foregroundColor(.secondary)
                    }
                    
                    Text("Today's Tracking")
                        .font(.title2)
                        .fontWeight(.semibold)
                        .padding(.top)
                }
                .padding(.horizontal)
                
                // Compounds List
                VStack(spacing: 16) {
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
                .padding(.horizontal)
                
                // Save Button
                Button(action: saveLog) {
                    HStack {
                        if isSaving {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                .scaleEffect(0.8)
                        } else {
                            Image(systemName: "checkmark.circle.fill")
                        }
                        Text(isSaving ? "Saving..." : "Save Today's Log")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
                }
                .disabled(isSaving)
                .padding(.horizontal)
                .padding(.top)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            initializeStates()
        }
        .alert("Success", isPresented: $showingSaveSuccess) {
            Button("OK") { }
        } message: {
            Text("Today's log saved successfully!")
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
            Button("Retry") {
                saveLog()
            }
        } message: {
            Text(errorMessage)
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
        isSaving = true
        
        apiService.saveProtocolLog(
            protocolId: protocol.id,
            compounds: compoundStates,
            notes: compoundNotes
        ) { result in
            DispatchQueue.main.async {
                isSaving = false
                switch result {
                case .success:
                    showingSaveSuccess = true
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
