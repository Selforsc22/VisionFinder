/**
 * VisionFinder Wearable - ESP32 BLE Recording Device Detector
 *
 * Detects nearby Bluetooth recording devices (smart glasses, action cameras)
 * and alerts via LED, buzzer, and/or haptic feedback.
 *
 * Based on research from:
 * - Nearby Glasses app (Yves Jeanrenaud)
 * - Banrays project
 * - Bluetooth SIG assigned numbers
 *
 * Hardware:
 * - ESP32 DevKit or similar
 * - LED (built-in or external on GPIO 2)
 * - Optional: Buzzer on GPIO 4
 * - Optional: Vibration motor on GPIO 5
 *
 * Detection method:
 * Primary: BLE manufacturer ID (mandatory, can't be spoofed)
 * Secondary: MAC address prefix (OUI)
 * Tertiary: Device name patterns
 */

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// Pin definitions
#define LED_PIN         2    // Built-in LED on most ESP32 boards
#define BUZZER_PIN      4    // Optional piezo buzzer
#define VIBRATION_PIN   5    // Optional vibration motor
#define BUTTON_PIN      0    // Boot button for mute

// Scan settings
#define SCAN_TIME       3    // Scan duration in seconds
#define RSSI_THRESHOLD  -75  // Only alert for devices stronger than this

// Alert settings
#define ALERT_DURATION_MS   2000
#define BLINK_INTERVAL_MS   100
#define COOLDOWN_MS         10000  // Don't re-alert same device for 10 seconds

// Verified BLE Manufacturer IDs from Bluetooth SIG
// These are mandatory identifiers that cannot be spoofed
struct ManufacturerID {
    uint16_t id;
    const char* name;
    bool has_camera;
};

const ManufacturerID THREAT_MANUFACTURER_IDS[] = {
    {0x01AB, "Meta Platforms (Ray-Ban)", true},           // Primary Meta ID
    {0x058E, "Meta Platforms Technologies", true},        // Meta Tech
    {0x0D53, "Luxottica (Ray-Ban)", true},               // Ray-Ban parent
    {0x03C2, "Snap Inc. (Spectacles)", true},            // Snapchat
    {0x00AB, "Amazon (Echo Frames)", false},             // Amazon - mic only
    {0x00E0, "Google (Glass)", true},                    // Google Glass
    {0x028E, "GoPro", true},                             // GoPro cameras
    {0x02C2, "DJI", true},                               // DJI action cams
    {0x0485, "Vuzix", true},                             // Vuzix glasses
    {0x0157, "Xiaomi (Smart Glasses)", true},            // Xiaomi
    {0x027D, "Huawei (Eyewear)", false},                 // Huawei - mic only
};
const int NUM_THREAT_IDS = sizeof(THREAT_MANUFACTURER_IDS) / sizeof(ManufacturerID);

// MAC address prefixes (OUI) for known recording devices
const char* THREAT_MAC_PREFIXES[] = {
    "E4:F0:42",  // Meta
    "9C:B6:D0",  // Meta
    "64:A2:F9",  // Meta
    "3C:28:6D",  // Meta
    "D4:D9:19",  // GoPro
    "24:A0:74",  // GoPro
    "60:60:1F",  // DJI
    "F8:8F:CA",  // Google
    "54:60:09",  // Google
};
const int NUM_MAC_PREFIXES = sizeof(THREAT_MAC_PREFIXES) / sizeof(char*);

// Device name patterns to match (case-insensitive)
const char* THREAT_NAME_PATTERNS[] = {
    "ray-ban",
    "spectacles",
    "meta",
    "gopro",
    "hero",
    "glass",
    "vuzix",
    "insta360",
    "osmo",
    "dji",
    "oakley",
};
const int NUM_NAME_PATTERNS = sizeof(THREAT_NAME_PATTERNS) / sizeof(char*);

// State
BLEScan* pBLEScan;
bool alertActive = false;
unsigned long alertStartTime = 0;
unsigned long lastAlertTime = 0;
String lastAlertAddress = "";
bool muted = false;

// Statistics
int totalScans = 0;
int totalDevicesSeen = 0;
int totalThreatsDetected = 0;

class ThreatCallback : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        totalDevicesSeen++;

        // Check RSSI threshold
        int rssi = advertisedDevice.getRSSI();
        if (rssi < RSSI_THRESHOLD) {
            return;
        }

        String address = advertisedDevice.getAddress().toString().c_str();
        address.toUpperCase();

        bool isThreat = false;
        const char* threatName = "Unknown Recording Device";
        bool hasCamera = true;

        // Check manufacturer ID (most reliable)
        if (advertisedDevice.haveManufacturerData()) {
            String mfrData = advertisedDevice.getManufacturerData();
            if (mfrData.length() >= 2) {
                uint16_t mfrId = (uint8_t)mfrData[0] | ((uint8_t)mfrData[1] << 8);

                for (int i = 0; i < NUM_THREAT_IDS; i++) {
                    if (mfrId == THREAT_MANUFACTURER_IDS[i].id) {
                        isThreat = true;
                        threatName = THREAT_MANUFACTURER_IDS[i].name;
                        hasCamera = THREAT_MANUFACTURER_IDS[i].has_camera;
                        Serial.printf("[MFR ID] Matched 0x%04X: %s\n", mfrId, threatName);
                        break;
                    }
                }
            }
        }

        // Check MAC prefix if not already matched
        if (!isThreat) {
            for (int i = 0; i < NUM_MAC_PREFIXES; i++) {
                if (address.startsWith(THREAT_MAC_PREFIXES[i])) {
                    isThreat = true;
                    threatName = "Recording Device (MAC match)";
                    Serial.printf("[MAC] Matched prefix %s\n", THREAT_MAC_PREFIXES[i]);
                    break;
                }
            }
        }

        // Check device name patterns if not already matched
        if (!isThreat && advertisedDevice.haveName()) {
            String name = advertisedDevice.getName().c_str();
            name.toLowerCase();

            for (int i = 0; i < NUM_NAME_PATTERNS; i++) {
                if (name.indexOf(THREAT_NAME_PATTERNS[i]) >= 0) {
                    isThreat = true;
                    threatName = "Recording Device (name match)";
                    Serial.printf("[NAME] Matched pattern '%s' in '%s'\n",
                                  THREAT_NAME_PATTERNS[i], advertisedDevice.getName().c_str());
                    break;
                }
            }
        }

        if (isThreat) {
            // Check cooldown to avoid repeated alerts for same device
            unsigned long now = millis();
            if (address != lastAlertAddress || (now - lastAlertTime) > COOLDOWN_MS) {
                totalThreatsDetected++;
                lastAlertAddress = address;
                lastAlertTime = now;

                Serial.println("========================================");
                Serial.println("!!! RECORDING DEVICE DETECTED !!!");
                Serial.printf("Device: %s\n", threatName);
                Serial.printf("Address: %s\n", address.c_str());
                Serial.printf("RSSI: %d dBm\n", rssi);
                Serial.printf("Has Camera: %s\n", hasCamera ? "YES" : "No (mic only)");
                if (advertisedDevice.haveName()) {
                    Serial.printf("Name: %s\n", advertisedDevice.getName().c_str());
                }
                Serial.println("========================================");

                if (!muted) {
                    triggerAlert(hasCamera);
                }
            }
        }
    }
};

void triggerAlert(bool hasCamera) {
    alertActive = true;
    alertStartTime = millis();

    // Different alert patterns for camera vs mic-only devices
    if (hasCamera) {
        // Urgent pattern for camera devices
        for (int i = 0; i < 5; i++) {
            digitalWrite(LED_PIN, HIGH);
            if (BUZZER_PIN >= 0) tone(BUZZER_PIN, 2000, 100);
            if (VIBRATION_PIN >= 0) digitalWrite(VIBRATION_PIN, HIGH);
            delay(100);
            digitalWrite(LED_PIN, LOW);
            if (VIBRATION_PIN >= 0) digitalWrite(VIBRATION_PIN, LOW);
            delay(100);
        }
    } else {
        // Less urgent pattern for mic-only devices
        for (int i = 0; i < 3; i++) {
            digitalWrite(LED_PIN, HIGH);
            if (BUZZER_PIN >= 0) tone(BUZZER_PIN, 1000, 200);
            if (VIBRATION_PIN >= 0) digitalWrite(VIBRATION_PIN, HIGH);
            delay(200);
            digitalWrite(LED_PIN, LOW);
            if (VIBRATION_PIN >= 0) digitalWrite(VIBRATION_PIN, LOW);
            delay(200);
        }
    }
}

void setup() {
    Serial.begin(115200);
    Serial.println("\n========================================");
    Serial.println("  VisionFinder Wearable Detector v2.0");
    Serial.println("  Recording Device Scanner");
    Serial.println("========================================");

    // Initialize pins
    pinMode(LED_PIN, OUTPUT);
    pinMode(BUTTON_PIN, INPUT_PULLUP);

    if (BUZZER_PIN >= 0) {
        pinMode(BUZZER_PIN, OUTPUT);
    }
    if (VIBRATION_PIN >= 0) {
        pinMode(VIBRATION_PIN, OUTPUT);
    }

    // Initialize BLE
    BLEDevice::init("VisionFinder");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new ThreatCallback());
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);

    // Startup indication
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_PIN, HIGH);
        delay(100);
        digitalWrite(LED_PIN, LOW);
        delay(100);
    }

    Serial.println("Monitoring for recording devices...");
    Serial.printf("RSSI threshold: %d dBm\n", RSSI_THRESHOLD);
    Serial.printf("Tracking %d manufacturer IDs, %d MAC prefixes, %d name patterns\n",
                  NUM_THREAT_IDS, NUM_MAC_PREFIXES, NUM_NAME_PATTERNS);
    Serial.println("Press BOOT button to mute/unmute alerts");
    Serial.println("========================================\n");
}

void loop() {
    // Check mute button
    static bool lastButtonState = HIGH;
    bool buttonState = digitalRead(BUTTON_PIN);
    if (lastButtonState == HIGH && buttonState == LOW) {
        muted = !muted;
        Serial.printf("Alerts %s\n", muted ? "MUTED" : "UNMUTED");

        // Feedback
        if (muted) {
            digitalWrite(LED_PIN, HIGH);
            delay(500);
            digitalWrite(LED_PIN, LOW);
        } else {
            for (int i = 0; i < 2; i++) {
                digitalWrite(LED_PIN, HIGH);
                delay(100);
                digitalWrite(LED_PIN, LOW);
                delay(100);
            }
        }
    }
    lastButtonState = buttonState;

    // Run BLE scan
    totalScans++;
    BLEScanResults results = pBLEScan->start(SCAN_TIME, false);
    pBLEScan->clearResults();

    // Heartbeat LED blink every 10 scans
    if (totalScans % 10 == 0) {
        digitalWrite(LED_PIN, HIGH);
        delay(50);
        digitalWrite(LED_PIN, LOW);

        // Print stats every 10 scans
        Serial.printf("[Stats] Scans: %d | Devices: %d | Threats: %d\n",
                      totalScans, totalDevicesSeen, totalThreatsDetected);
    }

    delay(100);
}
