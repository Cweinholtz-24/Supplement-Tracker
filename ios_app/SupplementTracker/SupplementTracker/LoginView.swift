
//
//  LoginView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct LoginView: View {
    @EnvironmentObject var apiService: APIService
    @Binding var isLoggedIn: Bool
    
    @State private var username = ""
    @State private var password = ""
    @State private var isLoading = false
    @State private var errorMessage = ""
    
    var body: some View {
        VStack(spacing: 20) {
            VStack(spacing: 10) {
                Image(systemName: "pills.circle.fill")
                    .font(.system(size: 80))
                    .foregroundColor(.blue)
                
                Text("Supplement Tracker")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                
                Text("Track your supplement protocols")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            .padding(.bottom, 40)
            
            VStack(spacing: 15) {
                TextField("Username", text: $username)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                
                SecureField("Password", text: $password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                
                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .foregroundColor(.red)
                        .font(.caption)
                }
                
                Button(action: {
                    loginUser()
                }) {
                    if isLoading {
                        HStack {
                            ProgressView()
                                .scaleEffect(0.8)
                            Text("Logging in...")
                        }
                    } else {
                        Text("Login")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(username.isEmpty || password.isEmpty || isLoading)
                
                Button(action: {
                    // Handle registration - could navigate to registration view
                    // For now, show message
                    errorMessage = "Registration available on web app"
                }) {
                    Text("Create Account")
                        .foregroundColor(.blue)
                }
            }
            .padding(.horizontal, 40)
            
            Spacer()
        }
        .padding()
    }
    
    private func loginUser() {
        isLoading = true
        errorMessage = ""
        
        apiService.login(username: username, password: password) { result in
            DispatchQueue.main.async {
                isLoading = false
                
                switch result {
                case .success:
                    isLoggedIn = true
                case .failure(let error):
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
}

struct LoginView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView(isLoggedIn: .constant(false))
            .environmentObject(APIService())
    }
}
