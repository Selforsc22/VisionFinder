"""
Bluetooth Device Scanner Module
Scans for nearby BLE devices and identifies potential recording devices
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False
    BLEDevice = None
    AdvertisementData = None

logger = logging.getLogger(__name__)


@dataclass
class DeviceSignature:
    """Represents a known recording device signature"""
    id: str
    name: str
    manufacturer: str
    device_type: str
    has_camera: bool
    has_microphone: bool
    threat_level: str
    name_patterns: list[str] = field(default_factory=list)
    manufacturer_prefixes: list[str] = field(default_factory=list)
    service_uuids: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class DetectedDevice:
    """Represents a detected Bluetooth device"""
    address: str
    name: Optional[str]
    rssi: int
    first_seen: datetime
    last_seen: datetime
    manufacturer_data: dict = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)
    matched_signature: Optional[DeviceSignature] = None
    is_potential_threat: bool = False
    threat_level: str = "unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "address": self.address,
            "name": self.name or "Unknown",
            "rssi": self.rssi,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "manufacturer_data": {str(k): v.hex() if isinstance(v, bytes) else v
                                  for k, v in self.manufacturer_data.items()},
            "service_uuids": self.service_uuids,
            "is_potential_threat": self.is_potential_threat,
            "threat_level": self.threat_level,
            "matched_device": self.matched_signature.name if self.matched_signature else None,
            "matched_device_type": self.matched_signature.device_type if self.matched_signature else None,
            "has_camera": self.matched_signature.has_camera if self.matched_signature else None,
            "has_microphone": self.matched_signature.has_microphone if self.matched_signature else None,
        }


class RecordingDeviceDatabase:
    """Manages the database of known recording device signatures"""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent / "data" / "recording_devices.json"
        self.db_path = db_path
        self.signatures: list[DeviceSignature] = []
        self.threat_levels: dict = {}
        self.load_database()

    def load_database(self):
        """Load the device signatures database"""
        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)

            self.threat_levels = data.get("threat_levels", {})

            for device in data.get("devices", []):
                identifiers = device.get("identifiers", {})
                signature = DeviceSignature(
                    id=device["id"],
                    name=device["name"],
                    manufacturer=device["manufacturer"],
                    device_type=device["type"],
                    has_camera=device.get("has_camera", False),
                    has_microphone=device.get("has_microphone", False),
                    threat_level=device.get("threat_level", "unknown"),
                    name_patterns=identifiers.get("name_patterns", []),
                    manufacturer_prefixes=identifiers.get("manufacturer_prefixes", []),
                    service_uuids=identifiers.get("service_uuids", []),
                    notes=device.get("notes", "")
                )
                self.signatures.append(signature)

            logger.info(f"Loaded {len(self.signatures)} device signatures from database")
        except FileNotFoundError:
            logger.warning(f"Device database not found at {self.db_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing device database: {e}")

    def match_device(self, name: Optional[str], address: str,
                     service_uuids: list[str]) -> Optional[DeviceSignature]:
        """
        Try to match a detected device against known signatures
        Returns the matching signature or None
        """
        address_upper = address.upper()

        for sig in self.signatures:
            # Check MAC address prefix
            for prefix in sig.manufacturer_prefixes:
                if address_upper.startswith(prefix.upper()):
                    logger.debug(f"Matched device {address} by MAC prefix {prefix}")
                    return sig

            # Check device name patterns
            if name:
                name_lower = name.lower()
                for pattern in sig.name_patterns:
                    if pattern.lower() in name_lower:
                        logger.debug(f"Matched device '{name}' by name pattern '{pattern}'")
                        return sig

            # Check service UUIDs
            for uuid in service_uuids:
                if uuid.lower() in [s.lower() for s in sig.service_uuids]:
                    logger.debug(f"Matched device {address} by service UUID {uuid}")
                    return sig

        return None


class BluetoothScanner:
    """Main Bluetooth scanner class"""

    def __init__(self, device_db: Optional[RecordingDeviceDatabase] = None):
        self.device_db = device_db or RecordingDeviceDatabase()
        self.detected_devices: dict[str, DetectedDevice] = {}
        self.scanning = False
        self._scan_task: Optional[asyncio.Task] = None
        self.on_device_detected: Optional[Callable[[DetectedDevice], None]] = None
        self.on_threat_detected: Optional[Callable[[DetectedDevice], None]] = None

        if not BLEAK_AVAILABLE:
            logger.warning("Bleak library not available - running in simulation mode")

    def _process_device(self, device: 'BLEDevice', advertisement_data: 'AdvertisementData'):
        """Process a detected BLE device"""
        now = datetime.now()
        address = device.address

        # Extract service UUIDs
        service_uuids = []
        if advertisement_data and advertisement_data.service_uuids:
            service_uuids = list(advertisement_data.service_uuids)

        # Extract manufacturer data
        manufacturer_data = {}
        if advertisement_data and advertisement_data.manufacturer_data:
            manufacturer_data = dict(advertisement_data.manufacturer_data)

        # Check if we've seen this device before
        if address in self.detected_devices:
            existing = self.detected_devices[address]
            existing.last_seen = now
            existing.rssi = advertisement_data.rssi if advertisement_data else -100
            if device.name and device.name != existing.name:
                existing.name = device.name
                # Re-check for threats if name changed
                self._check_for_threat(existing, service_uuids)
        else:
            # New device
            detected = DetectedDevice(
                address=address,
                name=device.name,
                rssi=advertisement_data.rssi if advertisement_data else -100,
                first_seen=now,
                last_seen=now,
                manufacturer_data=manufacturer_data,
                service_uuids=service_uuids,
            )

            self._check_for_threat(detected, service_uuids)
            self.detected_devices[address] = detected

            if self.on_device_detected:
                self.on_device_detected(detected)

            if detected.is_potential_threat and self.on_threat_detected:
                self.on_threat_detected(detected)

    def _check_for_threat(self, device: DetectedDevice, service_uuids: list[str]):
        """Check if a device matches known recording device signatures"""
        match = self.device_db.match_device(
            device.name,
            device.address,
            service_uuids
        )

        if match:
            device.matched_signature = match
            device.is_potential_threat = True
            device.threat_level = match.threat_level
            logger.warning(f"THREAT DETECTED: {match.name} at {device.address}")

    async def scan_once(self, timeout: float = 10.0) -> list[DetectedDevice]:
        """Perform a single scan and return detected devices"""
        if not BLEAK_AVAILABLE:
            logger.warning("Bleak not available - returning simulated data")
            return self._get_simulated_devices()

        logger.info(f"Starting BLE scan (timeout: {timeout}s)")

        try:
            devices = await BleakScanner.discover(
                timeout=timeout,
                return_adv=True
            )

            for device, adv_data in devices.values():
                self._process_device(device, adv_data)

            logger.info(f"Scan complete. Found {len(self.detected_devices)} devices")
            return list(self.detected_devices.values())

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            raise

    async def start_continuous_scan(self, callback: Optional[Callable] = None):
        """Start continuous background scanning"""
        if self.scanning:
            logger.warning("Scanner already running")
            return

        self.scanning = True

        if not BLEAK_AVAILABLE:
            logger.warning("Bleak not available - running in simulation mode")
            self._scan_task = asyncio.create_task(self._simulated_continuous_scan(callback))
            return

        def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            self._process_device(device, advertisement_data)
            if callback:
                callback(self.detected_devices.get(device.address))

        try:
            scanner = BleakScanner(detection_callback=detection_callback)
            await scanner.start()
            logger.info("Continuous scanning started")

            while self.scanning:
                await asyncio.sleep(1)

            await scanner.stop()
            logger.info("Continuous scanning stopped")

        except Exception as e:
            logger.error(f"Error in continuous scan: {e}")
            self.scanning = False
            raise

    async def _simulated_continuous_scan(self, callback: Optional[Callable] = None):
        """Simulated continuous scanning for testing without Bluetooth hardware"""
        import random

        simulated_devices = [
            ("AA:BB:CC:DD:EE:01", "iPhone", -65),
            ("AA:BB:CC:DD:EE:02", "Galaxy Watch", -70),
            ("AA:BB:CC:DD:EE:03", "AirPods Pro", -55),
            ("E4:F0:42:11:22:33", "Ray-Ban | Meta", -45),  # Simulated threat
            ("AA:BB:CC:DD:EE:04", "Fitbit", -80),
            ("AA:BB:CC:DD:EE:05", "Unknown Device", -90),
            ("AA:BB:CC:DD:EE:06", "Spectacles", -60),  # Simulated threat
            ("AA:BB:CC:DD:EE:07", "MacBook Pro", -75),
            ("D4:D9:19:AA:BB:CC", "GoPro HERO12", -50),  # Simulated threat
        ]

        logger.info("Starting simulated continuous scan")

        while self.scanning:
            # Randomly "discover" devices
            device_info = random.choice(simulated_devices)
            address, name, base_rssi = device_info

            now = datetime.now()
            rssi = base_rssi + random.randint(-10, 10)

            if address in self.detected_devices:
                self.detected_devices[address].last_seen = now
                self.detected_devices[address].rssi = rssi
            else:
                detected = DetectedDevice(
                    address=address,
                    name=name,
                    rssi=rssi,
                    first_seen=now,
                    last_seen=now,
                )
                self._check_for_threat(detected, [])
                self.detected_devices[address] = detected

                if self.on_device_detected:
                    self.on_device_detected(detected)

                if detected.is_potential_threat and self.on_threat_detected:
                    self.on_threat_detected(detected)

            if callback:
                callback(self.detected_devices[address])

            await asyncio.sleep(random.uniform(0.5, 2.0))

    def _get_simulated_devices(self) -> list[DetectedDevice]:
        """Return simulated devices for testing"""
        now = datetime.now()
        simulated = [
            DetectedDevice(
                address="AA:BB:CC:DD:EE:01",
                name="iPhone 15 Pro",
                rssi=-65,
                first_seen=now,
                last_seen=now,
            ),
            DetectedDevice(
                address="E4:F0:42:11:22:33",
                name="Ray-Ban | Meta",
                rssi=-45,
                first_seen=now,
                last_seen=now,
            ),
        ]

        for device in simulated:
            self._check_for_threat(device, [])
            self.detected_devices[device.address] = device

        return simulated

    def stop_scanning(self):
        """Stop continuous scanning"""
        self.scanning = False
        if self._scan_task:
            self._scan_task.cancel()

    def get_all_devices(self) -> list[DetectedDevice]:
        """Get all detected devices"""
        return list(self.detected_devices.values())

    def get_threats(self) -> list[DetectedDevice]:
        """Get only devices identified as potential threats"""
        return [d for d in self.detected_devices.values() if d.is_potential_threat]

    def clear_devices(self):
        """Clear the detected devices list"""
        self.detected_devices.clear()


# Simple test function
async def test_scanner():
    """Test the scanner functionality"""
    logging.basicConfig(level=logging.DEBUG)

    scanner = BluetoothScanner()

    def on_threat(device: DetectedDevice):
        print(f"ALERT! Recording device detected: {device.name} ({device.address})")

    scanner.on_threat_detected = on_threat

    print("Starting scan...")
    devices = await scanner.scan_once(timeout=5.0)

    print(f"\nFound {len(devices)} devices:")
    for device in devices:
        threat_indicator = " [THREAT]" if device.is_potential_threat else ""
        print(f"  {device.name or 'Unknown'} ({device.address}) RSSI: {device.rssi}{threat_indicator}")

    threats = scanner.get_threats()
    if threats:
        print(f"\n{len(threats)} potential recording device(s) detected!")
        for threat in threats:
            print(f"  - {threat.matched_signature.name}: {threat.address}")


if __name__ == "__main__":
    asyncio.run(test_scanner())
