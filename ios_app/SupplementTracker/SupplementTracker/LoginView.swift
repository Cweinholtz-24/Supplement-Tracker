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
            }
            .padding(.horizontal, 40)

            Spacer()
        }
        .alert("Login Failed", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
    }

    private func performLogin() {
        isLoading = true

        apiService.login(username: username, password: password) { result in
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