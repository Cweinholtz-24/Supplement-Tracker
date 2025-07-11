
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
    @State private var showingAlert = false
    @State private var alertMessage = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack {
                ScrollView {
                    VStack(spacing: 20) {
                        // Protocol Info Header
                        VStack(alignment: .leading, spacing: 8) {
                            Text(protocolItem.name)
                                .font(.title)
                                .fontWeight(.bold)

                            Text("Frequency: \(protocolItem.displayFrequency)")
                                .font(.subheadline)
                                .foregroundColor(.secondary)

                            if !protocolItem.displayDescription.isEmpty {
                                Text(protocolItem.displayDescription)
                                    .font(.body)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(Color(.systemGray6))
                        .cornerRadius(12)

                        // Compounds List
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Today's Compounds")
                                .font(.headline)
                                .fontWeight(.semibold)

                            ForEach(protocolItem.compounds, id: \.self) { compound in
                                CompoundChecklistItem(
                                    compound: compound,
                                    isChecked: Binding(
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

                        Spacer()
                    }
                    .padding()
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
                .padding()
            }
            .navigationTitle("Protocol Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("← Back") {
                        dismiss()
                    }
                }
            }
        }
        .onAppear {
            initializeStates()
        }
        .alert("Log Saved", isPresented: $showingAlert) {
            Button("OK") {
                dismiss()
            }
        } message: {
            Text(alertMessage)
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
                    alertMessage = "Successfully saved your supplement log for today!"
                    showingAlert = true
                case .failure(let error):
                    alertMessage = "Failed to save log: \(error.localizedDescription)"
                    showingAlert = true
                }
            }
        }
    }
}

struct CompoundChecklistItem: View {
    let compound: String
    @Binding var isChecked: Bool
    @Binding var note: String
    @State private var showingNoteField = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button(action: { isChecked.toggle() }) {
                    Image(systemName: isChecked ? "checkmark.circle.fill" : "circle")
                        .font(.title2)
                        .foregroundColor(isChecked ? .green : .gray)
                }
                .buttonStyle(PlainButtonStyle())

                Text(compound)
                    .font(.body)
                    .strikethrough(isChecked)
                    .foregroundColor(isChecked ? .secondary : .primary)

                Spacer()

                Button(action: { showingNoteField.toggle() }) {
                    Image(systemName: note.isEmpty ? "note" : "note.text")
                        .foregroundColor(note.isEmpty ? .gray : .blue)
                }
                .buttonStyle(PlainButtonStyle())
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
    ProtocolDetailView(protocolItem: ProtocolModel(
        id: "1",
        name: "Morning Stack",
        compounds: ["Vitamin D", "Omega-3", "Magnesium"],
        frequency: "Daily",
        description: "Essential morning supplements"
    ))
    .environmentObject(APIService.shared)
}