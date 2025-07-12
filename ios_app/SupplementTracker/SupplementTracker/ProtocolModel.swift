//
//  ProtocolModel.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation

struct CompoundDetail: Identifiable, Codable, Hashable {
    let id = UUID()
    let name: String
    let dailyDosage: String
    let timesPerDay: Int
    let unit: String

    enum CodingKeys: String, CodingKey {
        case name
        case dailyDosage = "daily_dosage"
        case timesPerDay = "times_per_day"
        case unit
    }

    init(name: String, dailyDosage: String = "1", timesPerDay: Int = 1, unit: String = "capsule") {
        self.name = name
        self.dailyDosage = dailyDosage
        self.timesPerDay = timesPerDay
        self.unit = unit
    }
}

struct ProtocolModel: Identifiable, Codable {
    let id: String
    let name: String
    let compounds: [CompoundDetail]
    var frequency: String?
    var description: String?
    var isActive: Bool?
    let createdAt: String?
    let updatedAt: String?
    let userId: Int?

    enum CodingKeys: String, CodingKey {
        case id, name, compounds, frequency, description, isActive, createdAt, updatedAt, userId
    }

    init(id: String, name: String, compounds: [CompoundDetail], frequency: String? = "Daily", description: String? = "", isActive: Bool? = true, createdAt: String? = nil, updatedAt: String? = nil, userId: Int? = nil) {
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
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        frequency = try container.decodeIfPresent(String.self, forKey: .frequency) ?? "Daily"
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        isActive = try container.decodeIfPresent(Bool.self, forKey: .isActive) ?? true
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt)
        updatedAt = try container.decodeIfPresent(String.self, forKey: .updatedAt)
        userId = try container.decodeIfPresent(Int.self, forKey: .userId)

        // Handle both old format (array of strings) and new format (array of objects)
        if let compoundObjects = try? container.decode([CompoundDetail].self, forKey: .compounds) {
            compounds = compoundObjects
        } else if let compoundStrings = try? container.decode([String].self, forKey: .compounds) {
            compounds = compoundStrings.map { CompoundDetail(name: $0) }
        } else {
            compounds = []
        }
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

struct DashboardSummary: Codable {
    let protocolsToday: Int
    let completedToday: Int
    let currentStreak: Int
    let adherenceRate: Double
}

struct EnhancedTrackingData: Codable {
    let mood: String?
    let energy: String?
    let sideEffects: String?
    let weight: String?
    let sleepHours: Double?
    let stressLevel: Int?
    let notes: String?
}

struct AdvancedAnalytics: Codable {
    let totalDays: Int
    let adherence: Double
    let streak: Int
    let missedDays: Int
    let compoundStats: [String: CompoundStats]
    let aiInsights: [AIInsight]
    let predictions: PredictionData
    let correlations: [CorrelationData]
    let weeklyTrends: [TrendData]
    let monthlyTrends: [TrendData]
}

struct AIInsight: Codable {
    let type: String
    let title: String
    let message: String
    let priority: String
}

struct PredictionData: Codable {
    let nextWeekAdherence: Double?
    let trend: String?
    let daysToReachGoal: Int?
}

struct CorrelationData: Codable {
    let date: String
    let adherence: Double
    let mood: String?
    let energy: String?
}

struct TrendData: Codable {
    let week: String?
    let month: String?
    let adherence: Double
}

struct ProtocolTemplate: Codable {
    let id: String
    let name: String
    let description: String
    let category: String
    let compounds: [CompoundDetail]
    let duration: String
    let difficulty: String
    let notes: String?
}

struct Achievement: Codable {
    let id: String
    let name: String
    let description: String
    let icon: String
    let points: Int
    let unlocked: Bool
}

struct UserLevel: Codable {
    let level: Int
    let title: String
    let totalPoints: Int
    let achievements: [Achievement]
}