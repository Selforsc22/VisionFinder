# Bluetooth Recording Device Scanner

A privacy-focused tool to detect and alert users about nearby Bluetooth-enabled video/audio recording devices such as Meta Ray-Bans, Snapchat Spectacles, GoPros, and other smart glasses or wearable cameras.

## Features

- **Real-time BLE Scanning**: Continuously monitors for nearby Bluetooth Low Energy devices
- **Recording Device Detection**: Identifies known recording devices by:
  - Device name patterns
  - MAC address prefixes (OUI)
  - Service UUIDs
- **Threat Alerting**: Visual and audio alerts when recording devices are detected
- **Web Dashboard**: Modern, real-time web UI for monitoring
- **Logging & History**: Persistent logging of all detections for analysis
- **Log Import**: Import logs from external Bluetooth scanning tools
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Known Recording Devices Database

The scanner includes signatures for detecting:

| Device | Manufacturer | Type | Camera | Mic |
|--------|--------------|------|--------|-----|
| Meta Ray-Ban Stories | Meta | Smart Glasses | Yes | Yes |
| Meta Ray-Ban (Gen 2) | Meta | Smart Glasses | Yes | Yes |
| Snapchat Spectacles | Snap Inc. | Smart Glasses | Yes | Yes |
| Amazon Echo Frames | Amazon | Smart Glasses | No | Yes |
| Google Glass | Google | Smart Glasses | Yes | Yes |
| Vuzix Blade | Vuzix | Smart Glasses | Yes | Yes |
| GoPro | GoPro | Action Camera | Yes | Yes |
| DJI Action/Osmo | DJI | Action Camera | Yes | Yes |
| Insta360 GO | Insta360 | Wearable Camera | Yes | Yes |
| And more... | | | | |

## Installation

### Prerequisites

- Python 3.10+
- Bluetooth adapter with BLE support
- Root/admin access may be required for Bluetooth scanning on some systems

### Setup

```bash
# Clone the repository
git clone https://github.com/Selforsc22/Selforsc22.git
cd Selforsc22

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Linux-specific Setup

On Linux, you may need to grant capabilities to Python or run as root:

```bash
# Option 1: Grant capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

# Option 2: Run as root (not recommended for production)
sudo python run.py
```

## Usage

### Web Interface (Recommended)

```bash
# Start the web server
python run.py

# With custom port
python run.py --port 8080

# Enable debug mode
python run.py --debug
```

Then open `http://localhost:5000` in your browser.

### Command Line Interface

```bash
# Single scan (10 seconds default)
python run.py --cli

# Extended scan
python run.py --cli --timeout 60

# Continuous scanning
python run.py --cli --continuous
```

## Web Interface Features

### Dashboard Overview
- Real-time device count statistics
- Threat count with severity breakdown
- Live connection status

### Threat Detection Panel
- Highlighted list of detected recording devices
- Device type identification (camera/microphone capabilities)
- Signal strength indicator
- Timestamp of detection

### All Devices View
- Complete list of nearby Bluetooth devices
- RSSI signal strength visualization
- Device address and name

### Alert History
- Log of all past threat detections
- Acknowledge alerts to mark as reviewed
- Persistent storage for forensic analysis

### Log Import
Import logs from external tools in JSON, CSV, or TXT format:
- Supports standard Bluetooth scan exports
- Automatically analyzes imported devices for threats
- Useful for batch analysis of pre-collected data

## API Endpoints

The web server exposes REST API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Scanner status |
| `/api/devices` | GET | All detected devices |
| `/api/threats` | GET | Detected threats only |
| `/api/history` | GET | Device history from logs |
| `/api/alerts` | GET | Alert history |
| `/api/alerts/<id>/acknowledge` | POST | Acknowledge an alert |
| `/api/statistics` | GET | Scanning statistics |
| `/api/signatures` | GET | Known device signatures |
| `/api/export/csv` | GET | Export to CSV |

## WebSocket Events

Real-time updates via Socket.IO:

| Event | Direction | Description |
|-------|-----------|-------------|
| `start_scan` | Client→Server | Start scanning |
| `stop_scan` | Client→Server | Stop scanning |
| `device_detected` | Server→Client | New device found |
| `threat_alert` | Server→Client | Recording device detected |
| `device_update` | Server→Client | Device info updated |

## Project Structure

```
Selforsc22/
├── run.py                 # Main entry point
├── requirements.txt       # Python dependencies
├── src/
│   ├── __init__.py
│   ├── scanner.py         # BLE scanner core
│   ├── device_logger.py   # Logging system
│   └── web_app.py         # Flask web application
├── data/
│   └── recording_devices.json  # Known device signatures
├── templates/
│   └── index.html         # Web UI template
├── static/
│   ├── css/
│   │   └── style.css      # UI styles
│   └── js/
│       └── app.js         # Frontend JavaScript
└── logs/                  # Detection logs (auto-created)
```

## Adding Custom Device Signatures

Edit `data/recording_devices.json` to add new device signatures:

```json
{
  "id": "custom_device",
  "name": "Custom Recording Device",
  "manufacturer": "Manufacturer Name",
  "type": "smart_glasses",
  "has_camera": true,
  "has_microphone": true,
  "threat_level": "high",
  "identifiers": {
    "name_patterns": ["Device Name", "DEVICE"],
    "manufacturer_prefixes": ["AA:BB:CC"],
    "service_uuids": ["0000xxxx-0000-1000-8000-00805f9b34fb"]
  },
  "notes": "Description of the device"
}
```

## Threat Levels

| Level | Description | Alert |
|-------|-------------|-------|
| **High** | Device has camera capability | Yes |
| **Medium** | Device has microphone only | Yes |
| **Low** | Minimal recording capability | No |

## Simulation Mode

When running without Bluetooth hardware (or if the `bleak` library cannot access Bluetooth), the scanner automatically enters simulation mode with sample devices for testing and development.

## Privacy & Legal Notice

This tool is intended for **personal privacy awareness** purposes only. Please:

- Respect others' privacy and personal property
- Follow all applicable local laws regarding surveillance detection
- Do not use this tool to harass, stalk, or intimidate others
- Be aware that device detection is not 100% accurate

## Troubleshooting

### "Bluetooth adapter not found"
- Ensure your system has a Bluetooth adapter
- Check that Bluetooth is enabled
- Try `hciconfig` on Linux to verify adapter status

### "Permission denied"
- Linux: Grant capabilities or run as root (see Installation)
- Windows: Run as Administrator
- macOS: Grant Bluetooth permissions in System Preferences

### "No devices found"
- Ensure Bluetooth devices are in range and advertising
- Some devices only advertise when not connected
- Try increasing scan timeout with `--timeout`

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - See LICENSE file for details.

## Disclaimer

This software is provided "as is" without warranty. The authors are not responsible for any misuse or for any damages resulting from the use of this software.
