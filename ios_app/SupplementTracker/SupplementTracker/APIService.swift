
//
//  APIService.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation
import SwiftUI
import Combine

class APIService: ObservableObject {
    static let shared = APIService()
    
    // Your actual Replit app URL
    private let baseURL = "https://suptidetracker.replit.app"
    
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
                // Save session cookies for future requests
                if let headerFields = httpResponse.allHeaderFields as? [String: String],
                   let url = httpResponse.url {
                    let cookies = HTTPCookie.cookies(withResponseHeaderFields: headerFields, for: url)
                    HTTPCookieStorage.shared.setCookies(cookies, for: url, mainDocumentURL: nil)
                }
                
                DispatchQueue.main.async {
                    self.isAuthenticated = true
                    self.saveAuthToken(username) // Save username instead of dummy token
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
    
    func createProtocol(name: String, compounds: [String], completion: @escaping (Result<ProtocolModel, Error>) -> Void) {
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
    
    func saveProtocolLog(protocolId: String, compounds: [String: Bool], notes: [String: String], completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/api/protocols/\(protocolId)/log") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
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

struct CreateProtocolRequest: Codable {
    let name: String
    let compounds: [String]
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
