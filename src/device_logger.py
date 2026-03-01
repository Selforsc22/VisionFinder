"""
Device Logger Module
Logs detected Bluetooth devices to files for analysis and history
"""

import csv
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .scanner import DetectedDevice

logger = logging.getLogger(__name__)


class DeviceLogger:
    """Logs detected devices to various formats"""

    def __init__(self, log_dir: Optional[Path] = None):
        if log_dir is None:
            log_dir = Path(__file__).parent.parent / "logs"

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.db_path = self.log_dir / "device_history.db"
        self._init_database()

        self.json_log_path = self.log_dir / "device_log.json"
        self.csv_log_path = self.log_dir / "device_log.csv"
        self.threat_log_path = self.log_dir / "threat_alerts.json"

    def _init_database(self):
        """Initialize SQLite database for device logging"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                name TEXT,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                times_seen INTEGER DEFAULT 1,
                is_threat BOOLEAN DEFAULT FALSE,
                threat_level TEXT,
                matched_device TEXT,
                notes TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_address TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                rssi INTEGER,
                manufacturer_data TEXT,
                service_uuids TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_address TEXT NOT NULL,
                device_name TEXT,
                matched_device TEXT,
                threat_level TEXT,
                timestamp TIMESTAMP NOT NULL,
                acknowledged BOOLEAN DEFAULT FALSE
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_address ON devices(address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_address ON detections(device_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")

        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")

    def log_device(self, device: DetectedDevice):
        """Log a detected device to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Check if device exists
            cursor.execute(
                "SELECT id, times_seen FROM devices WHERE address = ?",
                (device.address,)
            )
            result = cursor.fetchone()

            if result:
                # Update existing device
                device_id, times_seen = result
                cursor.execute("""
                    UPDATE devices
                    SET name = COALESCE(?, name),
                        last_seen = ?,
                        times_seen = ?,
                        is_threat = ?,
                        threat_level = ?,
                        matched_device = ?
                    WHERE id = ?
                """, (
                    device.name,
                    device.last_seen.isoformat(),
                    times_seen + 1,
                    device.is_potential_threat,
                    device.threat_level,
                    device.matched_signature.name if device.matched_signature else None,
                    device_id
                ))
            else:
                # Insert new device
                cursor.execute("""
                    INSERT INTO devices (address, name, first_seen, last_seen, is_threat, threat_level, matched_device)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    device.address,
                    device.name,
                    device.first_seen.isoformat(),
                    device.last_seen.isoformat(),
                    device.is_potential_threat,
                    device.threat_level,
                    device.matched_signature.name if device.matched_signature else None
                ))

            # Log the detection
            cursor.execute("""
                INSERT INTO detections (device_address, timestamp, rssi, manufacturer_data, service_uuids)
                VALUES (?, ?, ?, ?, ?)
            """, (
                device.address,
                datetime.now().isoformat(),
                device.rssi,
                json.dumps({str(k): v.hex() if isinstance(v, bytes) else str(v)
                           for k, v in device.manufacturer_data.items()}),
                json.dumps(device.service_uuids)
            ))

            conn.commit()
            logger.debug(f"Logged device: {device.address}")

        except Exception as e:
            logger.error(f"Error logging device: {e}")
            conn.rollback()
        finally:
            conn.close()

    def log_threat_alert(self, device: DetectedDevice):
        """Log a threat alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO alerts (device_address, device_name, matched_device, threat_level, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                device.address,
                device.name,
                device.matched_signature.name if device.matched_signature else None,
                device.threat_level,
                datetime.now().isoformat()
            ))
            conn.commit()
            logger.info(f"Logged threat alert for: {device.address}")

        except Exception as e:
            logger.error(f"Error logging threat alert: {e}")
            conn.rollback()
        finally:
            conn.close()

        # Also append to JSON log file
        self._append_to_json_log(device, is_threat=True)

    def _append_to_json_log(self, device: DetectedDevice, is_threat: bool = False):
        """Append device to JSON log file"""
        log_path = self.threat_log_path if is_threat else self.json_log_path

        try:
            if log_path.exists():
                with open(log_path, 'r') as f:
                    data = json.load(f)
            else:
                data = {"entries": []}

            entry = {
                "timestamp": datetime.now().isoformat(),
                "device": device.to_dict()
            }
            data["entries"].append(entry)

            with open(log_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Error writing to JSON log: {e}")

    def export_to_csv(self, output_path: Optional[Path] = None) -> Path:
        """Export all devices to CSV"""
        if output_path is None:
            output_path = self.csv_log_path

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT address, name, first_seen, last_seen, times_seen,
                       is_threat, threat_level, matched_device
                FROM devices
                ORDER BY last_seen DESC
            """)

            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Address', 'Name', 'First Seen', 'Last Seen',
                    'Times Seen', 'Is Threat', 'Threat Level', 'Matched Device'
                ])
                writer.writerows(cursor.fetchall())

            logger.info(f"Exported devices to {output_path}")
            return output_path

        finally:
            conn.close()

    def get_device_history(self, address: str) -> list[dict]:
        """Get detection history for a specific device"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT timestamp, rssi, manufacturer_data, service_uuids
                FROM detections
                WHERE device_address = ?
                ORDER BY timestamp DESC
                LIMIT 100
            """, (address,))

            columns = ['timestamp', 'rssi', 'manufacturer_data', 'service_uuids']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_all_devices(self, threats_only: bool = False) -> list[dict]:
        """Get all logged devices"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            query = """
                SELECT address, name, first_seen, last_seen, times_seen,
                       is_threat, threat_level, matched_device
                FROM devices
            """
            if threats_only:
                query += " WHERE is_threat = 1"
            query += " ORDER BY last_seen DESC"

            cursor.execute(query)

            columns = ['address', 'name', 'first_seen', 'last_seen', 'times_seen',
                       'is_threat', 'threat_level', 'matched_device']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        """Get recent threat alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT id, device_address, device_name, matched_device,
                       threat_level, timestamp, acknowledged
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))

            columns = ['id', 'device_address', 'device_name', 'matched_device',
                       'threat_level', 'timestamp', 'acknowledged']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        finally:
            conn.close()

    def acknowledge_alert(self, alert_id: int):
        """Mark an alert as acknowledged"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,)
            )
            conn.commit()
        finally:
            conn.close()

    def get_statistics(self) -> dict:
        """Get scanning statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            stats = {}

            # Total devices
            cursor.execute("SELECT COUNT(*) FROM devices")
            stats['total_devices'] = cursor.fetchone()[0]

            # Threat devices
            cursor.execute("SELECT COUNT(*) FROM devices WHERE is_threat = 1")
            stats['threat_devices'] = cursor.fetchone()[0]

            # Total detections
            cursor.execute("SELECT COUNT(*) FROM detections")
            stats['total_detections'] = cursor.fetchone()[0]

            # Total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            stats['total_alerts'] = cursor.fetchone()[0]

            # Unacknowledged alerts
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0")
            stats['unacknowledged_alerts'] = cursor.fetchone()[0]

            # Threat level breakdown
            cursor.execute("""
                SELECT threat_level, COUNT(*)
                FROM devices
                WHERE is_threat = 1
                GROUP BY threat_level
            """)
            stats['threat_breakdown'] = dict(cursor.fetchall())

            return stats
        finally:
            conn.close()

    def clear_old_detections(self, days: int = 30):
        """Clear detection records older than specified days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM detections
                WHERE timestamp < datetime('now', ?)
            """, (f'-{days} days',))
            deleted = cursor.rowcount
            conn.commit()
            logger.info(f"Cleared {deleted} old detection records")
            return deleted
        finally:
            conn.close()
