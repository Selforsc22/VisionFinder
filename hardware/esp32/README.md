# VisionFinder Wearable - ESP32 BLE Detector

A wearable Bluetooth recording device detector based on ESP32. Alerts you via LED, buzzer, and/or vibration when smart glasses or action cameras are detected nearby.

## Features

- **Real-time BLE scanning** - Continuous monitoring for nearby devices
- **Multi-method detection**:
  - BLE Manufacturer ID (most reliable - can't be spoofed)
  - MAC address prefix (OUI)
  - Device name patterns
- **Multiple alert modes**: LED, piezo buzzer, vibration motor
- **Different alerts** for camera vs mic-only devices
- **Mute button** to silence alerts
- **Statistics tracking** - devices seen, threats detected

## Detected Devices

| Manufacturer ID | Device |
|----------------|--------|
| `0x01AB` | Meta Platforms (Ray-Ban Smart Glasses) |
| `0x058E` | Meta Platforms Technologies |
| `0x0D53` | Luxottica (Ray-Ban) |
| `0x03C2` | Snap Inc. (Spectacles) |
| `0x00AB` | Amazon (Echo Frames) |
| `0x00E0` | Google (Glass) |
| `0x028E` | GoPro |
| `0x02C2` | DJI |
| `0x0485` | Vuzix |

## Hardware Required

### Minimal Build
- ESP32 DevKit (or any ESP32 board with BLE)
- That's it! Uses built-in LED.

### Full Build
- ESP32 DevKit
- Piezo buzzer (connected to GPIO 4)
- Vibration motor (connected to GPIO 5)
- 3.7V LiPo battery + charging module
- Small enclosure (3D printed or commercial)

### Wiring

```
ESP32 Pin   Component
---------   ---------
GPIO 2      Built-in LED (or external LED + 220Ω resistor)
GPIO 4      Piezo buzzer (positive terminal)
GPIO 5      Vibration motor (via NPN transistor)
GPIO 0      Boot button (built-in, for mute)
GND         Common ground
```

## Installation

### Using Arduino IDE

1. Install Arduino IDE
2. Add ESP32 board support:
   - File → Preferences → Additional Boards Manager URLs
   - Add: `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. Tools → Board → Boards Manager → Search "ESP32" → Install
4. Open `visionfinder_wearable.ino`
5. Select your board (e.g., "ESP32 Dev Module")
6. Upload

### Using PlatformIO

```bash
# Create platformio.ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200

# Build and upload
pio run -t upload
```

## Usage

1. Power on the ESP32
2. LED blinks 3 times on startup
3. Device continuously scans for threats
4. When a recording device is detected:
   - Camera device: 5 rapid blinks + high beeps
   - Mic-only device: 3 slower blinks + lower beeps
5. Press BOOT button to mute/unmute

## Configuration

Edit these values in the code:

```cpp
#define RSSI_THRESHOLD  -75  // Detection range (~10-15m)
#define SCAN_TIME       3    // Seconds per scan cycle
#define COOLDOWN_MS     10000 // Re-alert delay for same device
```

## Serial Monitor Output

```
========================================
  VisionFinder Wearable Detector v2.0
========================================
Monitoring for recording devices...

[MFR ID] Matched 0x01AB: Meta Platforms (Ray-Ban)
========================================
!!! RECORDING DEVICE DETECTED !!!
Device: Meta Platforms (Ray-Ban)
Address: E4:F0:42:11:22:33
RSSI: -45 dBm
Has Camera: YES
Name: Ray-Ban | Meta
========================================

[Stats] Scans: 10 | Devices: 47 | Threats: 1
```

## Enclosure Ideas

### Pendant/Necklace
- Small 3D printed case
- Battery on back
- LED visible through translucent cover

### Glasses Clip
- Tiny board (ESP32-C3 Mini)
- Coin cell battery
- Clips to temple of existing glasses

### Wristband
- Flexible PCB
- Integrated vibration motor
- Discreet alerts

## Power Consumption

- Active scanning: ~100mA
- With 500mAh LiPo: ~4-5 hours continuous use
- Deep sleep between scans can extend to 20+ hours

## Adding New Devices

Edit the `THREAT_MANUFACTURER_IDS` array:

```cpp
{0xNNNN, "Device Name", true},  // true = has camera
```

Find manufacturer IDs at: https://www.bluetooth.com/specifications/assigned-numbers/

## License

MIT License - See main project LICENSE
