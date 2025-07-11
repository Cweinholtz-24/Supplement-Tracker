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
    var frequency: String?
    var description: String?
    var isActive: Bool?
    let createdAt: String?
    let updatedAt: String?
    let userId: Int?

    // Custom initializer to handle default values
    init(id: String, name: String, compounds: [String], frequency: String? = "Daily", description: String? = "", isActive: Bool? = true, createdAt: String? = nil, updatedAt: String? = nil, userId: Int? = nil) {
        self.id = id
        self.name = name
        self.compounds = compounds
        self.frequency = frequency
        self.description = description
        self.isActive = isActive
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.userId = userId
    }
    
    // Computed properties for safe access with defaults
    var displayFrequency: String {
        frequency ?? "Daily"
    }
    
    var displayDescription: String {
        description ?? ""
    }
    
    var displayIsActive: Bool {
        isActive ?? true
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

struct AnalyticsModel: Codable {
    let totalDays: Int
    let adherence: Double
    let streak: Int
    let missedDays: Int
    let compoundStats: [String: CompoundStats]
}

struct CompoundStats: Codable {
    let taken: Int
    let missed: Int
    let percentage: Double
}

struct NotificationModel: Identifiable, Codable {
    let id: String
    let title: String
    let message: String
    let type: String
    let isRead: Bool
    let createdAt: String
}