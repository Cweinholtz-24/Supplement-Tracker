
# Supplement Tracker iOS App

This iOS app integrates with your Flask webapp running on Replit to provide a native mobile experience for tracking supplement protocols.

## Features

- **Native iOS Interface**: Clean, modern SwiftUI design
- **Protocol Management**: View and track your supplement protocols
- **Daily Logging**: Check off compounds and add notes
- **Sync with Web App**: All data syncs with your Replit webapp
- **Offline Support**: Basic offline functionality (planned)

## Setup Instructions

1. **Open in Xcode**: Open `SupplementTracker.xcodeproj` in Xcode
2. **Update API URL**: In `APIService.swift`, replace the `baseURL` with your actual Replit app URL:
   ```swift
   private let baseURL = "https://your-repl-name.your-username.repl.co"
   ```
3. **Build and Run**: Select your target device and hit Run

## API Integration

The iOS app communicates with your Flask webapp through these endpoints:

- `POST /api/login` - User authentication
- `GET /api/protocols` - Fetch user protocols
- `POST /api/protocols/:id/log` - Save daily logs
- `GET /api/protocols/:id/history` - Get protocol history
- `GET /api/user/profile` - Get user profile

## Architecture

- **SwiftUI**: Modern declarative UI framework
- **Combine**: Reactive programming for data flow
- **URLSession**: HTTP networking with your Flask API
- **UserDefaults**: Simple local storage for auth tokens

## Current Status

This is a basic implementation that provides:
- Login screen
- Protocol dashboard
- Daily tracking interface
- API communication structure

## Future Enhancements

- Push notifications for reminders
- Apple Health integration
- Offline data caching
- Enhanced analytics and charts
- Widget support
- 2FA integration

## Testing

Currently uses mock data for testing. Once your API endpoints are fully implemented, the app will sync with your live data.

## Deployment

To deploy to the App Store:
1. Add proper code signing
2. Update bundle identifier
3. Add app icons and launch screens
4. Test on physical devices
5. Submit through App Store Connect
