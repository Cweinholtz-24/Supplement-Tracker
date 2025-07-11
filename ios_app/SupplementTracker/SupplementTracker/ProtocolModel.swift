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
    let createdAt: String?

    init(id: String, name: String, compounds: [String], createdAt: String? = nil) {
        self.id = id
        self.name = name
        self.compounds = compounds
        self.createdAt = createdAt
    }
}

struct ProtocolLog: Identifiable, Codable {
    let id: String
    let protocolId: String
    let date: String
    let compounds: [String: CompoundEntry]
    let mood: String?
    let energy: String?
    let sideEffects: String?
    let weight: String?
    let generalNotes: String?
}

struct CompoundEntry: Codable {
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
    let createdAt: String
    let protocolCount: Int
}