
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
    let frequency: String
    let description: String
    let createdAt: String?

    enum CodingKeys: String, CodingKey {
        case id, name, compounds, frequency, description, createdAt
    }
    
    init(id: String, name: String, compounds: [String], frequency: String = "Daily", description: String = "", createdAt: String? = nil) {
        self.id = id
        self.name = name
        self.compounds = compounds
        self.frequency = frequency
        self.description = description
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

struct CalendarEvent: Identifiable, Codable {
    let id = UUID()
    let date: String
    let taken: Int
    let total: Int
    let missed: Int
    let completed: Bool
    let entries: [String: CompoundEntry]
}

struct ReminderSettings: Codable {
    let enabled: Bool
    let time: String
    let protocols: [String]
    let frequency: String // daily, weekly, etc.
}

struct HealthMetrics: Codable {
    let date: String
    let weight: Double?
    let mood: Int? // 1-10 scale
    let energy: Int? // 1-10 scale
    let sleepHours: Double?
    let notes: String?
}

struct ExportData: Codable {
    let protocols: [ProtocolModel]
    let logs: [ProtocolLog]
    let profile: UserProfile
    let exportDate: String
    let version: String
}
