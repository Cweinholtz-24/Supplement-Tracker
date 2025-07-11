
//
//  ProtocolModel.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation

struct ProtocolModel: Identifiable, Codable {
    let id: String
    let name: String
    let compounds: [String]
    let createdAt: Date?
    
    init(id: String, name: String, compounds: [String], createdAt: Date? = nil) {
        self.id = id
        self.name = name
        self.compounds = compounds
        self.createdAt = createdAt
    }
}

struct ProtocolLog: Identifiable, Codable {
    let id: String
    let protocolId: String
    let date: Date
    let compounds: [String: CompoundLog]
    let mood: String?
    let energy: String?
    let sideEffects: String?
    let weight: String?
    let generalNotes: String?
}

struct CompoundLog: Codable {
    let taken: Bool
    let note: String?
    
    init(taken: Bool, note: String? = nil) {
        self.taken = taken
        self.note = note
    }
}

struct UserProfile: Codable {
    let username: String
    let email: String?
    let createdAt: Date
    let protocolCount: Int
}
