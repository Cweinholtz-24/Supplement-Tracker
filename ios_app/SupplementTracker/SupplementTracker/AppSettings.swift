
//
//  AppSettings.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation
import SwiftUI

class AppSettings: ObservableObject {
    static let shared = AppSettings()
    
    @Published var notificationsEnabled: Bool {
        didSet {
            UserDefaults.standard.set(notificationsEnabled, forKey: "notifications_enabled")
        }
    }
    
    @Published var reminderTime: Date {
        didSet {
            UserDefaults.standard.set(reminderTime, forKey: "reminder_time")
            if notificationsEnabled {
                scheduleNotifications()
            }
        }
    }
    
    @Published var isDarkMode: Bool {
        didSet {
            UserDefaults.standard.set(isDarkMode, forKey: "dark_mode")
        }
    }
    
    @Published var hapticFeedbackEnabled: Bool {
        didSet {
            UserDefaults.standard.set(hapticFeedbackEnabled, forKey: "haptic_feedback")
        }
    }
    
    @Published var autoSync: Bool {
        didSet {
            UserDefaults.standard.set(autoSync, forKey: "auto_sync")
        }
    }
    
    private init() {
        self.notificationsEnabled = UserDefaults.standard.object(forKey: "notifications_enabled") as? Bool ?? true
        self.reminderTime = UserDefaults.standard.object(forKey: "reminder_time") as? Date ?? Calendar.current.date(bySettingHour: 9, minute: 0, second: 0, of: Date()) ?? Date()
        self.isDarkMode = UserDefaults.standard.object(forKey: "dark_mode") as? Bool ?? false
        self.hapticFeedbackEnabled = UserDefaults.standard.object(forKey: "haptic_feedback") as? Bool ?? true
        self.autoSync = UserDefaults.standard.object(forKey: "auto_sync") as? Bool ?? true
    }
    
    private func scheduleNotifications() {
        // Implementation would go here to schedule local notifications
        // This would integrate with the APIService notification scheduling
    }
}
