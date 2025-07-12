//
//  APIService.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation
import SwiftUI
import Combine
import UserNotifications

class APIService: ObservableObject {
    static let shared = APIService()

    // Your actual Replit app URL
    private let baseURL = "https://suptidetracker.replit.app"

    @Published var isAuthenticated = false
    @Published var authToken: String?
    @Published var notifications: [NotificationModel] = []
    @Published var requires2FA = false
    @Published var pendingUsername: String?

    private var cancellables = Set<AnyCancellable>()

    init() {
        // Load saved auth token if exists
        loadAuthToken()
        setupNotifications()
    }

    // MARK: - Notifications Setup

    private func setupNotifications() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { granted, error in
            if granted {
                print("Notification permission granted")
                DispatchQueue.main.async {
                    UIApplication.shared.registerForRemoteNotifications()
                }
            }
        }
    }

    func scheduleReminderNotification(for protocolName: String, at time: Date) {
        let content = UNMutableNotificationContent()
        content.title = "Supplement Reminder"
        content.body = "Time to log your \(protocolName) protocol!"
        content.sound = .default
        content.badge = 1

        let calendar = Calendar.current
        let components = calendar.dateComponents([.hour, .minute], from: time)
        let trigger = UNCalendarNotificationTrigger(dateMatching: components, repeats: true)

        let request = UNNotificationRequest(identifier: "protocol-\(protocolName)", content: content, trigger: trigger)

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("Error scheduling notification: \(error)")
            }
        }
    }

    // MARK: - Authentication

    func login(username: String, password: String, completion: @escaping (Result<LoginResponse, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/login") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let loginData = LoginRequest(username: username, password: password)

        do {
            request.httpBody = try JSONEncoder().encode(loginData)
        } catch {
            completion(.failure(error))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  let data = data else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 200 {
                do {
                    let loginResponse = try JSONDecoder().decode(LoginResponse.self, from: data)

                    if loginResponse.requires2FA == true {
                        DispatchQueue.main.async {
                            self.requires2FA = true
                            self.pendingUsername = username
                        }
                        completion(.success(loginResponse))
                    } else {
                        // Save session cookies for future requests
                        if let headerFields = httpResponse.allHeaderFields as? [String: String],
                           let url = httpResponse.url {
                            let cookies = HTTPCookie.cookies(withResponseHeaderFields: headerFields, for: url)
                            HTTPCookieStorage.shared.setCookies(cookies, for: url, mainDocumentURL: nil)
                        }

                        DispatchQueue.main.async {
                            self.isAuthenticated = true
                            self.requires2FA = false
                            self.saveAuthToken(username)
                        }
                        completion(.success(loginResponse))
                    }
                } catch {
                    completion(.failure(error))
                }
            } else {
                completion(.failure(APIError.loginFailed))
            }
        }.resume()
    }

    func verify2FA(code: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/verify_2fa") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let twoFAData = TwoFARequest(code: code)

        do {
            request.httpBody = try JSONEncoder().encode(twoFAData)
        } catch {
            completion(.failure(error))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 200 {
                // Save session cookies for future requests
                if let headerFields = httpResponse.allHeaderFields as? [String: String],
                   let url = httpResponse.url {
                    let cookies = HTTPCookie.cookies(withResponseHeaderFields: headerFields, for: url)
                    HTTPCookieStorage.shared.setCookies(cookies, for: url, mainDocumentURL: nil)
                }

                DispatchQueue.main.async {
                    self.isAuthenticated = true
                    self.requires2FA = false
                    if let username = self.pendingUsername {
                        self.saveAuthToken(username)
                    }
                    self.pendingUsername = nil
                }
                completion(.success(()))
            } else {
                completion(.failure(APIError.twoFAFailed))
            }
        }.resume()
    }

    func logout() {
        authToken = nil
        isAuthenticated = false
        requires2FA = false
        pendingUsername = nil
        clearAuthToken()

        // Clear cookies
        if let cookies = HTTPCookieStorage.shared.cookies {
            for cookie in cookies {
                HTTPCookieStorage.shared.deleteCookie(cookie)
            }
        }
    }

    // MARK: - Protocols

    func fetchProtocols(completion: @escaping (Result<[ProtocolModel], Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 401 {
                DispatchQueue.main.async {
                    self.isAuthenticated = false
                    self.clearAuthToken()
                }
                completion(.failure(APIError.loginFailed))
                return
            }

            guard let data = data else {
                completion(.failure(APIError.noData))
                return
            }

            do {
                let protocols = try JSONDecoder().decode([ProtocolModel].self, from: data)
                completion(.success(protocols))
            } catch {
                print("JSON decode error: \(error)")
                completion(.failure(error))
            }
        }.resume()
    }

    func fetchAvailableCompounds(completion: @escaping (Result<[String], Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/compounds") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  let data = data else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 200 {
                do {
                    let response = try JSONDecoder().decode(CompoundsResponse.self, from: data)
                    completion(.success(response.compounds))
                } catch {
                    completion(.failure(error))
                }
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }

    func addCustomCompound(name: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/compounds") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let requestData = AddCompoundRequest(name: name)

        do {
            request.httpBody = try JSONEncoder().encode(requestData)
        } catch {
            completion(.failure(error))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 201 {
                completion(.success(()))
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }

    func createProtocol(name: String, compounds: [CompoundDetail], completion: @escaping (Result<ProtocolModel, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let requestData = CreateProtocolRequest(name: name, compounds: compounds)

        do {
            request.httpBody = try JSONEncoder().encode(requestData)
        } catch {
            completion(.failure(error))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 401 {
                DispatchQueue.main.async {
                    self.isAuthenticated = false
                    self.clearAuthToken()
                }
                completion(.failure(APIError.loginFailed))
                return
            }

            guard let data = data else {
                completion(.failure(APIError.noData))
                return
            }

            if httpResponse.statusCode == 201 {
                do {
                    let protocolResponse = try JSONDecoder().decode(ProtocolModel.self, from: data)
                    completion(.success(protocolResponse))
                } catch {
                    completion(.failure(error))
                }
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }

    func saveProtocolLog(protocolId: String, compounds: [String: Bool], notes: [String: String], dosages: [String: String] = [:], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/\(protocolId)/log") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let logData = ProtocolLogRequest(compounds: compounds, notes: notes, dosages: dosages)

        do {
            request.httpBody = try JSONEncoder().encode(logData)
        } catch {
            completion(.failure(error))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 401 {
                DispatchQueue.main.async {
                    self.isAuthenticated = false
                    self.clearAuthToken()
                }
                completion(.failure(APIError.loginFailed))
                return
            }

            if httpResponse.statusCode == 200 {
                completion(.success(()))
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }

    // MARK: - Analytics

    func fetchProtocolAnalytics(protocolId: String, completion: @escaping (Result<AnalyticsModel, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/\(protocolId)/analytics") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  let data = data else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 401 {
                DispatchQueue.main.async {
                    self.isAuthenticated = false
                    self.clearAuthToken()
                }
                completion(.failure(APIError.loginFailed))
                return
            }

            if httpResponse.statusCode == 200 {
                do {
                    let analytics = try JSONDecoder().decode(AnalyticsModel.self, from: data)
                    completion(.success(analytics))
                } catch {
                    completion(.failure(error))
                }
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }
    
    // MARK: - Advanced Analytics
    
    func fetchProtocolTemplates(completion: @escaping (Result<[ProtocolTemplate], Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/templates") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        performRequest(url: url, method: "GET", body: nil, completion: completion)
    }
    
    func createProtocolFromTemplate(templateId: String, customName: String?, completion: @escaping (Result<ProtocolModel, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/from-template") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["templateId": templateId, "customName": customName ?? ""]
        performRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func syncWearableData(deviceType: String, metrics: [String: Any], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/wearables/sync") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["deviceType": deviceType, "metrics": metrics]
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: requestData)
        } catch {
            completion(.failure(error))
            return
        }
        
        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }
            
            if httpResponse.statusCode == 200 {
                completion(.success(()))
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }
    
    func saveBiomarkerData(biomarkers: [BiomarkerData], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/biomarkers") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["biomarkers": biomarkers.map { $0.toDictionary() }]
        performVoidRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func fetchBiomarkers(completion: @escaping (Result<[BiomarkerData], Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/biomarkers") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        performRequest(url: url, method: "GET", body: nil, completion: completion)
    }
    
    func processVoiceCommand(command: String, completion: @escaping (Result<VoiceCommandResponse, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/voice-commands") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["command": command]
        performRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func scanBarcode(barcode: String, completion: @escaping (Result<BarcodeScanResult, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/barcode/scan") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["barcode": barcode]
        performRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func fetchAchievements(completion: @escaping (Result<AchievementsData, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/gamification/achievements") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        performRequest(url: url, method: "GET", body: nil, completion: completion)
    }
    
    func fetchAdvancedAnalytics(protocolId: String, completion: @escaping (Result<EnhancedAnalyticsModel, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/\(protocolId)/analytics/advanced") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        performRequest(url: url, method: "GET", body: nil, completion: completion)
    }
    
    func createProtocolFromTemplate(templateId: String, customName: String?, completion: @escaping (Result<ProtocolModel, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/from-template") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["templateId": templateId, "customName": customName ?? ""]
        performRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func manageProtocolCycles(protocolId: String, cycleConfig: [String: Any], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/cycles") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["protocolId": protocolId, "cycleConfig": cycleConfig]
        performVoidRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func trackSupplementCosts(costs: [SupplementCost], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/cost-tracking") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["costs": costs.map { $0.toDictionary() }]
        performVoidRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func setupSmartReminders(protocolId: String, reminderConfig: [String: Any], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/reminders/smart") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        let requestData = ["protocolId": protocolId, "reminderConfig": reminderConfig]
        performVoidRequest(url: url, method: "POST", body: requestData, completion: completion)
    }
    
    func exportComprehensiveData(format: String, completion: @escaping (Result<ExportData, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/export/comprehensive?format=\(format)") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        performRequest(url: url, method: "GET", body: nil, completion: completion)
    }
    
    // MARK: - Helper Methods
    
    private func performRequest<T: Codable>(url: URL, method: String, body: [String: Any]?, completion: @escaping (Result<T, Error>) -> Void) {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        if let body = body {
            do {
                request.httpBody = try JSONSerialization.data(withJSONObject: body)
            } catch {
                completion(.failure(error))
                return
            }
        }
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse,
                  let data = data else {
                completion(.failure(APIError.invalidResponse))
                return
            }
            
            if httpResponse.statusCode == 401 {
                DispatchQueue.main.async {
                    self.isAuthenticated = false
                    self.clearAuthToken()
                }
                completion(.failure(APIError.loginFailed))
                return
            }
            
            if httpResponse.statusCode == 200 {
                do {
                    let result = try JSONDecoder().decode(T.self, from: data)
                    completion(.success(result))
                } catch {
                    completion(.failure(error))
                }
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }
    
    private func performVoidRequest(url: URL, method: String, body: [String: Any]?, completion: @escaping (Result<Void, Error>) -> Void) {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        if let body = body {
            do {
                request.httpBody = try JSONSerialization.data(withJSONObject: body)
            } catch {
                completion(.failure(error))
                return
            }
        }
        
        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }
            
            if httpResponse.statusCode == 200 || httpResponse.statusCode == 201 {
                completion(.success(()))
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }

    // MARK: - Notifications

    func fetchNotifications(completion: @escaping (Result<[NotificationModel], Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/notifications") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  let data = data else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 401 {
                DispatchQueue.main.async {
                    self.isAuthenticated = false
                    self.clearAuthToken()
                }
                completion(.failure(APIError.loginFailed))
                return
            }

            if httpResponse.statusCode == 200 {
                do {
                    let notifications = try JSONDecoder().decode([NotificationModel].self, from: data)
                    DispatchQueue.main.async {
                        self.notifications = notifications
                    }
                    completion(.success(notifications))
                } catch {
                    completion(.failure(error))
                }
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }

    func markNotificationAsRead(notificationId: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/notifications/\(notificationId)/read") else {
            completion(.failure(APIError.invalidURL))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }

            if httpResponse.statusCode == 200 {
                completion(.success(()))
            } else {
                completion(.failure(APIError.requestFailed))
            }
        }.resume()
    }

    // MARK: - Auth Token Management

    private func saveAuthToken(_ token: String) {
        authToken = token
        UserDefaults.standard.set(token, forKey: "auth_token")
    }

    private func loadAuthToken() {
        if let token = UserDefaults.standard.string(forKey: "auth_token") {
            authToken = token
            isAuthenticated = true
        }
    }

    private func clearAuthToken() {
        UserDefaults.standard.removeObject(forKey: "auth_token")
    }
}

// MARK: - Models

struct LoginRequest: Codable {
    let username: String
    let password: String
}

struct LoginResponse: Codable {
    let success: Bool?
    let requires2FA: Bool?
    let message: String
    let user: UserModel?
    let token: String?

    enum CodingKeys: String, CodingKey {
        case success, message, user, token
        case requires2FA = "requires_2fa"
    }
}

struct UserModel: Codable {
    let username: String
}

struct TwoFARequest: Codable {
    let code: String
}

struct CreateProtocolRequest: Codable {
    let name: String
    let compounds: [CompoundDetail]
}

struct CompoundsResponse: Codable {
    let compounds: [String]
}

struct AddCompoundRequest: Codable {
    let name: String
}

struct ProtocolLogRequest: Codable {
    let compounds: [String: Bool]
    let notes: [String: String]
    let dosages: [String: String]
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

enum APIError: Error {
    case invalidURL
    case invalidResponse
    case noData
    case loginFailed
    case twoFAFailed
    case requestFailed
    case networkError
    case serverError(Int)

    var localizedDescription: String {
        switch self {
        case .invalidURL:
            return "Invalid URL configuration"
        case .invalidResponse:
            return "Server returned an invalid response"
        case .noData:
            return "No data received from server"
        case .loginFailed:
            return "Invalid username or password"
        case .twoFAFailed:
            return "Invalid 2FA code. Please try again."
        case .requestFailed:
            return "Request failed. Please try again."
        case .networkError:
            return "Network connection error. Check your internet connection."
        case .serverError(let code):
            return "Server error (\(code)). Please try again later."
        }
    }

    var isRetryable: Bool {
        switch self {
        case .networkError, .serverError, .requestFailed:
            return true
        default:
            return false
        }
    }
}