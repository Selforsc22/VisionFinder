# VisionFinder Mobile App

A React Native/Expo mobile app for detecting nearby Bluetooth-enabled recording devices like Meta Ray-Bans, Snapchat Spectacles, and other smart glasses.

## Features

- Real-time BLE scanning for nearby devices
- Detects recording devices via manufacturer IDs (most reliable method)
- Push notifications when threats are detected
- Haptic feedback on threat detection
- Distance estimation based on signal strength
- Clean, dark-mode UI

## Detection Method

The app identifies recording devices using multiple methods:

1. **BLE Manufacturer ID** (most reliable)
   - `0x01AB` (427): Meta Platforms, Inc.
   - `0x058E` (1422): Meta Platforms Technologies, LLC
   - `0x0969` (2409): Woan Technology Shenzhen (glasses OEM)
   - `0x0D53` (3411): Luxottica Group S.p.A (Ray-Ban)

2. **MAC Address Prefix** (OUI)
3. **Device Name Patterns**

## Setup

### Prerequisites

- Node.js 18+
- Expo CLI: `npm install -g expo-cli`
- iOS: Xcode (for iOS simulator/builds)
- Android: Android Studio (for emulator/builds)

### Installation

```bash
cd mobile
npm install
```

### Running in Development

```bash
# Start Expo development server
npm start

# Run on iOS simulator
npm run ios

# Run on Android emulator
npm run android
```

### Building for Production

```bash
# Install EAS CLI
npm install -g eas-cli

# Configure EAS
eas build:configure

# Build for Android
eas build --platform android

# Build for iOS
eas build --platform ios
```

## Permissions Required

### iOS
- `NSBluetoothAlwaysUsageDescription` - Bluetooth scanning
- `UIBackgroundModes: bluetooth-central` - Background scanning

### Android
- `BLUETOOTH`, `BLUETOOTH_ADMIN` - Legacy Bluetooth
- `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT` - Android 12+
- `ACCESS_FINE_LOCATION` - Required for BLE scanning

## Usage

1. Open the app
2. Tap "Start Scanning"
3. The app will list all nearby Bluetooth devices
4. Recording devices are highlighted in red with warnings
5. You'll receive a notification + vibration when a threat is detected

## Limitations

- **False positives**: May detect Meta Quest VR headsets (same manufacturer IDs)
- **iOS Background**: Limited background scanning on iOS
- **Range**: Typical detection range is 3-15 meters depending on environment
- **Unpaired devices**: Most reliable when glasses are advertising (not connected)

## Project Structure

```
mobile/
├── App.tsx              # Main app component
├── store.ts             # Zustand state management
├── deviceSignatures.ts  # Known device database
├── app.json             # Expo configuration
├── package.json         # Dependencies
└── assets/              # Icons and sounds
```

## Contributing

To add new device signatures, edit `deviceSignatures.ts` and add entries to the `KNOWN_DEVICES` array with:
- Device name and manufacturer
- BLE manufacturer IDs (preferred)
- MAC address prefixes
- Name patterns to match
