
//
//  LoginView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct LoginView: View {
    @EnvironmentObject var apiService: APIService
    @State private var username = ""
    @State private var password = ""
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingError = false
    
    var body: some View {
        VStack(spacing: 30) {
            // App Logo/Title
            VStack(spacing: 16) {
                Image(systemName: "pills.fill")
                    .font(.system(size: 80))
                    .foregroundColor(.blue)
                
                Text("Supplement Tracker")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                
                Text("Track your supplement protocols")
                    .font(.body)
                    .foregroundColor(.secondary)
            }
            .padding(.top, 60)
            
            // Login Form
            VStack(spacing: 20) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Username")
                        .font(.headline)
                    
                    TextField("Enter username", text: $username)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
                
                VStack(alignment: .leading, spacing: 8) {
                    Text("Password")
                        .font(.headline)
                    
                    SecureField("Enter password", text: $password)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                }
                
                Button(action: performLogin) {
                    HStack {
                        if isLoading {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                .scaleEffect(0.8)
                        } else {
                            Image(systemName: "person.circle.fill")
                        }
                        Text(isLoading ? "Signing In..." : "Sign In")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(loginButtonColor)
                    .foregroundColor(.white)
                    .cornerRadius(12)
                }
                .disabled(isLoading || username.isEmpty || password.isEmpty)
            }
            .padding(.horizontal, 40)
            
            Spacer()
            
            // Footer
            VStack(spacing: 8) {
                Text("Demo Credentials:")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                Text("Username: demo_user")
                    .font(.caption)
                    .foregroundColor(.blue)
                    .onTapGesture {
                        username = "demo_user"
                    }
                
                Text("Password: password123")
                    .font(.caption)
                    .foregroundColor(.blue)
                    .onTapGesture {
                        password = "password123"
                    }
            }
            .padding(.bottom, 30)
        }
        .alert("Login Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
    }
    
    private var loginButtonColor: Color {
        if isLoading || username.isEmpty || password.isEmpty {
            return .gray
        } else {
            return .blue
        }
    }
    
    private func performLogin() {
        isLoading = true
        errorMessage = ""
        
        apiService.login(username: username, password: password) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    // APIService already sets isAuthenticated = true
                    break
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    showingError = true
                }
            }
        }
    }
}

#Preview {
    LoginView()
        .environmentObject(APIService.shared)
}
