
//
//  WidgetView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI
import WidgetKit

struct ProtocolWidgetView: View {
    let protocol: ProtocolModel
    let completionPercentage: Double
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(protocol.name)
                .font(.headline)
                .lineLimit(1)
            
            HStack {
                ForEach(protocol.compounds.prefix(3), id: \.self) { compound in
                    Circle()
                        .fill(Color.blue)
                        .frame(width: 8, height: 8)
                }
                
                if protocol.compounds.count > 3 {
                    Text("+\(protocol.compounds.count - 3)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Text("\(Int(completionPercentage))%")
                    .font(.caption)
                    .fontWeight(.semibold)
            }
            
            ProgressView(value: completionPercentage / 100)
                .progressViewStyle(LinearProgressViewStyle())
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

#Preview {
    ProtocolWidgetView(
        protocol: ProtocolModel(
            id: "1",
            name: "Morning Stack",
            compounds: ["Vitamin D", "Omega-3", "Magnesium"]
        ),
        completionPercentage: 75
    )
}
