
//
//  APIService.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation
import Combine

class APIService: ObservableObject {
    static let shared = APIService()
    
    // Replace this with your Replit app URL
    private let baseURL = "https://your-repl-name.your-username.repl.co"
    
    @Published var isAuthenticated = false
    @Published var authToken: String?
    
    private var cancellables = Set<AnyCancellable>()
    
    init() {
        // Load saved auth token if exists
        loadAuthToken()
    }
    
    // MARK: - Authentication
    
    func login(username: String, password: String, completion: @escaping (Result<Void, Error>) -> Void) {
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
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }
            
            if httpResponse.statusCode == 200 {
                // For now, we'll simulate successful login
                // In a real implementation, you'd parse the response for auth tokens
                DispatchQueue.main.async {
                    self.isAuthenticated = true
                    self.saveAuthToken("dummy_token")
                }
                completion(.success(()))
            } else {
                completion(.failure(APIError.loginFailed))
            }
        }.resume()
    }
    
    func logout() {
        authToken = nil
        isAuthenticated = false
        clearAuthToken()
    }
    
    // MARK: - Protocols
    
    func fetchProtocols(completion: @escaping (Result<[ProtocolModel], Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
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
                completion(.failure(error))
            }
        }.resume()
    }
    
    func saveProtocolLog(protocolId: String, compounds: [String: Bool], notes: [String: String], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/\(protocolId)/log") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        let logData = ProtocolLogRequest(compounds: compounds, notes: notes)
        
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

struct ProtocolLogRequest: Codable {
    let compounds: [String: Bool]
    let notes: [String: String]
}

enum APIError: Error {
    case invalidURL
    case invalidResponse
    case noData
    case loginFailed
    case requestFailed
    
    var localizedDescription: String {
        switch self {
        case .invalidURL:
            return "Invalid URL"
        case .invalidResponse:
            return "Invalid response"
        case .noData:
            return "No data received"
        case .loginFailed:
            return "Login failed"
        case .requestFailed:
            return "Request failed"
        }
    }
}
