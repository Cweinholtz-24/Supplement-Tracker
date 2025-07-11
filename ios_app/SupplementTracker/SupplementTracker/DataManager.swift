
//
//  DataManager.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation
import SwiftUI

class DataManager: ObservableObject {
    static let shared = DataManager()
    
    private let userDefaults = UserDefaults.standard
    private let protocolsKey = "cached_protocols"
    private let lastSyncKey = "last_sync_date"
    
    private init() {}
    
    // MARK: - Protocol Caching
    
    func cacheProtocols(_ protocols: [ProtocolModel]) {
        do {
            let data = try JSONEncoder().encode(protocols)
            userDefaults.set(data, forKey: protocolsKey)
            userDefaults.set(Date(), forKey: lastSyncKey)
        } catch {
            print("Failed to cache protocols: \(error)")
        }
    }
    
    func getCachedProtocols() -> [ProtocolModel]? {
        guard let data = userDefaults.data(forKey: protocolsKey) else {
            return nil
        }
        
        do {
            return try JSONDecoder().decode([ProtocolModel].self, from: data)
        } catch {
            print("Failed to decode cached protocols: \(error)")
            return nil
        }
    }
    
    func getLastSyncDate() -> Date? {
        return userDefaults.object(forKey: lastSyncKey) as? Date
    }
    
    func clearCache() {
        userDefaults.removeObject(forKey: protocolsKey)
        userDefaults.removeObject(forKey: lastSyncKey)
    }
    
    // MARK: - Pending Logs (for offline support)
    
    private let pendingLogsKey = "pending_logs"
    
    func savePendingLog(protocolId: String, compounds: [String: Bool], notes: [String: String]) {
        var pendingLogs = getPendingLogs()
        
        let logEntry = PendingLogEntry(
            id: UUID().uuidString,
            protocolId: protocolId,
            compounds: compounds,
            notes: notes,
            timestamp: Date()
        )
        
        pendingLogs.append(logEntry)
        
        do {
            let data = try JSONEncoder().encode(pendingLogs)
            userDefaults.set(data, forKey: pendingLogsKey)
        } catch {
            print("Failed to save pending log: \(error)")
        }
    }
    
    func getPendingLogs() -> [PendingLogEntry] {
        guard let data = userDefaults.data(forKey: pendingLogsKey) else {
            return []
        }
        
        do {
            return try JSONDecoder().decode([PendingLogEntry].self, from: data)
        } catch {
            print("Failed to decode pending logs: \(error)")
            return []
        }
    }
    
    func removePendingLog(withId id: String) {
        var pendingLogs = getPendingLogs()
        pendingLogs.removeAll { $0.id == id }
        
        do {
            let data = try JSONEncoder().encode(pendingLogs)
            userDefaults.set(data, forKey: pendingLogsKey)
        } catch {
            print("Failed to update pending logs: \(error)")
        }
    }
    
    func clearPendingLogs() {
        userDefaults.removeObject(forKey: pendingLogsKey)
    }
}

struct PendingLogEntry: Codable, Identifiable {
    let id: String
    let protocolId: String
    let compounds: [String: Bool]
    let notes: [String: String]
    let timestamp: Date
}
