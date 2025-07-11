
//
//  ProtocolDetailView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI
import Foundation

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
        print("Saving log for \(protocol.name)")
        print("Taken: \(todayLog)")
        print("Notes: \(notes)")
    }
}
