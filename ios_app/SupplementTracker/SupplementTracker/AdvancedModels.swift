
import Foundation

// MARK: - Advanced Analytics Models

struct ProtocolTemplate: Codable, Identifiable {
    let id: String
    let name: String
    let description: String
    let category: String
    let compounds: [CompoundDetail]
    let duration: String
    let difficulty: String
    let notes: String?
}

struct AIInsight: Codable, Identifiable {
    let id = UUID()
    let type: String
    let title: String
    let message: String
    let priority: String
    
    var priorityLevel: Int {
        switch priority {
        case "high": return 3
        case "medium": return 2
        default: return 1
        }
    }
    
    var iconName: String {
        switch type {
        case "success": return "checkmark.circle.fill"
        case "warning": return "exclamationmark.triangle.fill"
        case "alert": return "exclamationmark.circle.fill"
        case "achievement": return "star.fill"
        case "suggestion": return "lightbulb.fill"
        case "trending": return "chart.line.uptrend.xyaxis"
        default: return "info.circle.fill"
        }
    }
}

struct PredictionData: Codable {
    let nextWeekAdherence: Double?
    let trend: String?
    let daysToReachGoal: Int?
}

struct CorrelationData: Codable {
    let date: String
    let adherence: Double
    let mood: String
    let energy: String
}

struct WeeklyTrend: Codable, Identifiable {
    let id = UUID()
    let week: String
    let adherence: Double
}

struct MonthlyTrend: Codable, Identifiable {
    let id = UUID()
    let month: String
    let adherence: Double
}

struct BestPerformingDay: Codable {
    let day: String
    let adherence: Double
}

// MARK: - Protocol Management Models

struct ProtocolCycle: Codable {
    let protocolId: String
    let cycleType: String
    let onDays: Int
    let offDays: Int
    let startDate: String
    let isActive: Bool
}

struct ProtocolStack: Codable {
    let name: String
    let protocolIds: [String]
    let interactions: [String]
    let warnings: [String]
    let createdAt: String
}

struct SupplementCost: Codable {
    let compoundName: String
    let costPerUnit: Double
    let unitsPerBottle: Int
    let bottleCost: Double
    let supplier: String
    let purchaseDate: String
    let expiryDate: String?
}

struct CostTrackingData: Codable {
    let costs: [SupplementCost]
    let monthlyTotal: Double
    let yearlyEstimate: Double
}

// MARK: - Data Integration Models

struct BiomarkerData: Codable {
    let name: String
    let value: Double
    let unit: String
    let referenceMin: Double?
    let referenceMax: Double?
    let testDate: String
    let labName: String?
    let notes: String?
    
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "name": name,
            "value": value,
            "unit": unit,
            "testDate": testDate
        ]
        
        if let referenceMin = referenceMin { dict["referenceMin"] = referenceMin }
        if let referenceMax = referenceMax { dict["referenceMax"] = referenceMax }
        if let labName = labName { dict["labName"] = labName }
        if let notes = notes { dict["notes"] = notes }
        
        return dict
    }
}

// MARK: - Supplement Cost Extension
extension SupplementCost {
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "compoundName": compoundName,
            "costPerUnit": costPerUnit,
            "unitsPerBottle": unitsPerBottle,
            "bottleCost": bottleCost,
            "supplier": supplier,
            "purchaseDate": purchaseDate
        ]
        
        if let expiryDate = expiryDate { dict["expiryDate"] = expiryDate }
        
        return dict
    }
}

// MARK: - Additional Model Extensions
extension WearableMetric {
    func toDictionary() -> [String: Any] {
        return [
            "type": type,
            "value": value,
            "unit": unit,
            "date": date
        ]
    }
}

extension SmartReminder {
    func toDictionary() -> [String: Any] {
        return [
            "protocolId": protocolId,
            "type": type,
            "trigger": trigger,
            "message": message,
            "enabled": enabled
        ]
    }
    
    var isInRange: Bool {
        guard let min = referenceMin, let max = referenceMax else { return true }
        return value >= min && value <= max
    }
    
    var status: String {
        if isInRange {
            return "Normal"
        } else if let min = referenceMin, value < min {
            return "Below Normal"
        } else {
            return "Above Normal"
        }
    }
}

struct WearableMetric: Codable {
    let type: String
    let value: Double
    let unit: String
    let date: String
}

struct CorrelationAnalysis: Codable {
    let compound: String
    let metric: String
    let correlation: Double
    let strength: String
    let dataPoints: Int
}

// MARK: - Quality of Life Models

struct SmartReminder: Codable {
    let protocolId: String
    let type: String
    let trigger: String
    let message: String
    let enabled: Bool
}

struct VoiceCommandResponse: Codable {
    let success: Bool
    let message: String
    let action: String
    let data: [String: Any]?
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        success = try container.decode(Bool.self, forKey: .success)
        message = try container.decode(String.self, forKey: .message)
        action = try container.decode(String.self, forKey: .action)
        data = try container.decodeIfPresent([String: Any].self, forKey: .data)
    }
    
    private enum CodingKeys: String, CodingKey {
        case success, message, action, data
    }
}

struct BarcodeScanResult: Codable {
    let success: Bool
    let supplement: ScannedSupplement?
    let message: String
    let suggestion: String?
}

struct ScannedSupplement: Codable {
    let name: String
    let brand: String
    let dosage: String
    let unit: String
    let servingsPerBottle: Int
    let category: String
}

struct Achievement: Codable, Identifiable {
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
}

struct AchievementsData: Codable {
    let achievements: [Achievement]
    let totalPoints: Int
    let level: UserLevel
}

struct ExportData: Codable {
    let user: [String: String]
    let protocols: [[String: Any]]
    let logs: [[String: Any]]
    let biomarkers: [[String: Any]]
    let wearableData: [[String: Any]]
    let healthKitData: [[String: Any]]
    let costs: [[String: Any]]
}

// MARK: - Enhanced Analytics Model

struct EnhancedAnalyticsModel: Codable {
    let totalDays: Int
    let adherence: Double
    let streak: Int
    let missedDays: Int
    let compoundStats: [String: CompoundStats]
    let aiInsights: [AIInsight]
    let predictions: PredictionData
    let correlations: [CorrelationData]
    let weeklyTrends: [WeeklyTrend]
    let monthlyTrends: [MonthlyTrend]
    let bestPerformingDay: BestPerformingDay?
    let adherencePattern: String
}

// MARK: - Offline Support Models

struct OfflineLogEntry: Codable {
    let id: String
    let protocolName: String
    let date: String
    let compounds: [String: CompoundLogEntry]
    let timestamp: Date
    let synced: Bool
}

struct CompoundLogEntry: Codable {
    let taken: Bool
    let note: String
}
