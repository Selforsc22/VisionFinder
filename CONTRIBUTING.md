# Contributing Device Signatures

Help improve VisionFinder by contributing new device signatures! Your contributions help protect privacy for everyone.

## How to Contribute

### Option 1: GitHub Issue (Easiest)

Create an issue with the following information:

```
Device Name: [e.g., "Acme Smart Glasses X1"]
Manufacturer: [e.g., "Acme Corp"]
Has Camera: [Yes/No]
Has Microphone: [Yes/No]

Detection Info (any you can provide):
- BLE Manufacturer ID: [e.g., 0x1234]
- MAC Prefix: [e.g., "AA:BB:CC"]
- Device Name Pattern: [e.g., "Acme-"]
- Service UUIDs: [if known]

How verified: [e.g., "Own the device", "Found in FCC filing", "Research paper"]
```

### Option 2: Pull Request

1. Fork the repository
2. Edit `data/recording_devices.json`
3. Add your device following the schema below
4. Submit a PR with evidence/source

## Device Schema

```json
{
  "id": "unique_device_id",
  "name": "Human Readable Name",
  "manufacturer": "Company Name",
  "type": "smart_glasses|action_camera|wearable_camera|security_camera",
  "has_camera": true,
  "has_microphone": true,
  "threat_level": "high|medium|low",
  "identifiers": {
    "name_patterns": ["pattern1", "pattern2"],
    "manufacturer_prefixes": ["AA:BB:CC"],
    "ble_manufacturer_ids": [1234],
    "service_uuids": ["0000xxxx-0000-1000-8000-00805f9b34fb"]
  },
  "notes": "Additional context"
}
```

## Finding BLE Manufacturer IDs

### Method 1: nRF Connect App (Recommended)
1. Install "nRF Connect" on your phone
2. Scan for your device
3. Look for "Manufacturer Specific Data"
4. First 2 bytes (little-endian) = Company ID

### Method 2: Wireshark
1. Capture BLE traffic
2. Filter: `bthci_evt.le_advts_event`
3. Look for Company ID in advertising data

### Method 3: FCC Filings
1. Search [FCC ID database](https://www.fcc.gov/oet/ea/fccid)
2. Find test reports for the device
3. Look for Bluetooth test data

### Method 4: Bluetooth SIG Database
- [Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/)
- Search by company name

## Verification Guidelines

Signatures are accepted based on evidence quality:

| Evidence Type | Reliability |
|--------------|-------------|
| Hardware testing (you own it) | Highest |
| FCC/CE certification data | High |
| Manufacturer documentation | High |
| Wireshark captures | High |
| Research papers | Medium |
| User reports (multiple) | Medium |
| Single user report | Low |

## What We're Looking For

### High Priority
- New smart glasses models
- Wearable cameras (pendant, clip-on)
- Glasses from new manufacturers
- Updated IDs for existing devices

### Medium Priority
- Action cameras
- Body cameras
- Drone cameras with Bluetooth

### Lower Priority
- Fixed security cameras
- Dashcams
- Traditional camcorders

## Code of Conduct

- Only submit signatures for legitimate recording devices
- Do not submit false signatures to cause false positives
- Respect privacy - don't share personal device info
- Be helpful and constructive in discussions

## Questions?

Open an issue with the "question" label or join our discussions.

---

Thank you for helping protect privacy! 🛡️
