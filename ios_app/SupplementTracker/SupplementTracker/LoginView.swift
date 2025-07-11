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
    @State private var twoFACode = ""
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingError = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 30) {
                Spacer()

                // Logo/Header
                VStack(spacing: 16) {
                    Image(systemName: "pills.fill")
                        .font(.system(size: 60))
                        .foregroundColor(.blue)

                    Text("Supplement Tracker")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    Text("Track your supplement protocols")
                        .font(.body)
                        .foregroundColor(.secondary)
                }

                Spacer()

                // Login Form
                VStack(spacing: 20) {
                    if !apiService.requires2FA {
                        // Username and Password Fields
                        TextField("Username", text: $username)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .autocapitalization(.none)
                            .disableAutocorrection(true)

                        SecureField("Password", text: $password)
                            .textFieldStyle(RoundedBorderTextFieldStyle())

                        Button(action: performLogin) {
                            HStack {
                                if isLoading {
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                        .scaleEffect(0.8)
                                }
                                Text(isLoading ? "Logging in..." : "Login")
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(12)
                        }
                        .disabled(username.isEmpty || password.isEmpty || isLoading)
                    } else {
                        // 2FA Code Field
                        VStack(spacing: 16) {
                            Text("Two-Factor Authentication")
                                .font(.headline)
                                .fontWeight(.semibold)

                            Text("Enter the 6-digit code from your authenticator app")
                                .font(.body)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)

                            TextField("000000", text: $twoFACode)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .keyboardType(.numberPad)
                                .multilineTextAlignment(.center)
                                .font(.title2)
                                .onChange(of: twoFACode) { _ in
                                    handleTwoFACodeChange()
                                }

                            Button(action: verify2FA) {
                                HStack {
                                    if isLoading {
                                        ProgressView()
                                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                            .scaleEffect(0.8)
                                    }
                                    Text(isLoading ? "Verifying..." : "Verify Code")
                                        .fontWeight(.semibold)
                                }
                                .frame(maxWidth: .infinity)
                                .padding()
                                .background(Color.blue)
                                .foregroundColor(.white)
                                .cornerRadius(12)
                            }
                            .disabled(twoFACode.count != 6 || isLoading)

                            Button("← Back to Login") {
                                resetToLogin()
                            }
                            .foregroundColor(.blue)
                        }
                    }
                }
                .padding(.horizontal, 40)

                Spacer()
            }
            .alert("Authentication Failed", isPresented: $showingError) {
                Button("OK") { 
                    handleErrorOK()
                }
            } message: {
                Text(errorMessage)
            }
        }
    }

    private func handleTwoFACodeChange() {
        if twoFACode.count > 6 {
            twoFACode = String(twoFACode.prefix(6))
        }
    }

    private func resetToLogin() {
        apiService.requires2FA = false
        twoFACode = ""
    }

    private func handleErrorOK() {
        if apiService.requires2FA {
            twoFACode = ""
        }
    }

    private func performLogin() {
        isLoading = true

        apiService.login(username: username, password: password) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success(let response):
                    if response.requires2FA == true {
                        // 2FA required, UI will update automatically
                        break
                    }
                    // Login success is handled by apiService updating isAuthenticated
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    showingError = true
                }
            }
        }
    }

    private func verify2FA() {
        isLoading = true

        apiService.verify2FA(code: twoFACode) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success:
                    // Login success is handled by apiService updating isAuthenticated
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