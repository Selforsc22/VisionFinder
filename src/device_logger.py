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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dwell_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_address TEXT NOT NULL,
                session_start TIMESTAMP NOT NULL,
                session_end TIMESTAMP,
                total_dwell_seconds INTEGER DEFAULT 0,
                is_threat BOOLEAN DEFAULT FALSE,
                matched_device TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pattern_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_address TEXT NOT NULL,
                hour_of_day INTEGER,
                day_of_week INTEGER,
                detection_count INTEGER DEFAULT 1,
                avg_dwell_seconds REAL DEFAULT 0,
                last_updated TIMESTAMP
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_address ON devices(address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_address ON detections(device_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dwell_device ON dwell_sessions(device_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern_device ON pattern_analysis(device_address)")

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

    def start_dwell_session(self, device: DetectedDevice):
        """Start tracking a dwell session for a device"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO dwell_sessions (device_address, session_start, is_threat, matched_device)
                VALUES (?, ?, ?, ?)
            """, (
                device.address,
                datetime.now().isoformat(),
                device.is_potential_threat,
                device.matched_signature.name if device.matched_signature else None
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def end_dwell_session(self, device_address: str):
        """End the most recent dwell session for a device"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT id, session_start FROM dwell_sessions
                WHERE device_address = ? AND session_end IS NULL
                ORDER BY session_start DESC LIMIT 1
            """, (device_address,))
            result = cursor.fetchone()

            if result:
                session_id, start_str = result
                start_time = datetime.fromisoformat(start_str)
                end_time = datetime.now()
                dwell_seconds = int((end_time - start_time).total_seconds())

                cursor.execute("""
                    UPDATE dwell_sessions
                    SET session_end = ?, total_dwell_seconds = ?
                    WHERE id = ?
                """, (end_time.isoformat(), dwell_seconds, session_id))
                conn.commit()

                self._update_pattern_analysis(device_address, start_time, dwell_seconds, conn)
                return dwell_seconds
            return 0
        finally:
            conn.close()

    def _update_pattern_analysis(self, device_address: str, detection_time: datetime,
                                  dwell_seconds: int, conn: sqlite3.Connection):
        """Update pattern analysis for a device"""
        cursor = conn.cursor()
        hour = detection_time.hour
        day = detection_time.weekday()

        cursor.execute("""
            SELECT id, detection_count, avg_dwell_seconds FROM pattern_analysis
            WHERE device_address = ? AND hour_of_day = ? AND day_of_week = ?
        """, (device_address, hour, day))
        result = cursor.fetchone()

        if result:
            record_id, count, avg_dwell = result
            new_count = count + 1
            new_avg = ((avg_dwell * count) + dwell_seconds) / new_count
            cursor.execute("""
                UPDATE pattern_analysis
                SET detection_count = ?, avg_dwell_seconds = ?, last_updated = ?
                WHERE id = ?
            """, (new_count, new_avg, datetime.now().isoformat(), record_id))
        else:
            cursor.execute("""
                INSERT INTO pattern_analysis
                (device_address, hour_of_day, day_of_week, detection_count, avg_dwell_seconds, last_updated)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (device_address, hour, day, dwell_seconds, datetime.now().isoformat()))

        conn.commit()

    def get_device_patterns(self, device_address: str) -> dict:
        """Get pattern analysis for a specific device"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT hour_of_day, day_of_week, detection_count, avg_dwell_seconds
                FROM pattern_analysis
                WHERE device_address = ?
                ORDER BY detection_count DESC
            """, (device_address,))

            patterns = cursor.fetchall()
            hourly = [0] * 24
            daily = [0] * 7

            for hour, day, count, _ in patterns:
                hourly[hour] += count
                daily[day] += count

            cursor.execute("""
                SELECT COUNT(*), SUM(total_dwell_seconds), AVG(total_dwell_seconds)
                FROM dwell_sessions
                WHERE device_address = ? AND session_end IS NOT NULL
            """, (device_address,))
            sessions, total_dwell, avg_dwell = cursor.fetchone()

            return {
                'hourly_heatmap': hourly,
                'daily_heatmap': daily,
                'total_sessions': sessions or 0,
                'total_dwell_seconds': total_dwell or 0,
                'avg_dwell_seconds': round(avg_dwell or 0, 1),
                'patterns': [{'hour': h, 'day': d, 'count': c, 'avg_dwell': a}
                            for h, d, c, a in patterns]
            }
        finally:
            conn.close()

    def get_surveillance_report(self) -> dict:
        """Generate a surveillance analysis report for all threat devices"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT d.address, d.name, d.matched_device, d.times_seen,
                       COUNT(ds.id) as sessions,
                       SUM(ds.total_dwell_seconds) as total_dwell,
                       AVG(ds.total_dwell_seconds) as avg_dwell
                FROM devices d
                LEFT JOIN dwell_sessions ds ON d.address = ds.device_address
                WHERE d.is_threat = 1
                GROUP BY d.address
                ORDER BY total_dwell DESC
            """)

            threats = []
            for row in cursor.fetchall():
                addr, name, matched, times_seen, sessions, total_dwell, avg_dwell = row
                threats.append({
                    'address': addr,
                    'name': name,
                    'matched_device': matched,
                    'times_seen': times_seen,
                    'sessions': sessions or 0,
                    'total_dwell_seconds': total_dwell or 0,
                    'avg_dwell_seconds': round(avg_dwell or 0, 1),
                    'risk_score': self._calculate_risk_score(times_seen, sessions or 0, total_dwell or 0)
                })

            return {
                'total_threats': len(threats),
                'threats': threats,
                'high_risk_count': sum(1 for t in threats if t['risk_score'] >= 70),
                'generated_at': datetime.now().isoformat()
            }
        finally:
            conn.close()

    def _calculate_risk_score(self, times_seen: int, sessions: int, total_dwell: int) -> int:
        """Calculate a risk score (0-100) based on surveillance patterns"""
        score = 0
        score += min(times_seen * 5, 30)
        score += min(sessions * 10, 30)
        score += min(total_dwell // 60, 40)
        return min(score, 100)

    def export_signatures(self, output_path: Optional[Path] = None) -> Path:
        """Export detected threat signatures for community sharing"""
        if output_path is None:
            output_path = self.log_dir / "exported_signatures.json"

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT DISTINCT d.address, d.name, d.matched_device,
                       GROUP_CONCAT(DISTINCT det.manufacturer_data) as mfr_data
                FROM devices d
                JOIN detections det ON d.address = det.device_address
                WHERE d.is_threat = 1
                GROUP BY d.address
            """)

            signatures = []
            for addr, name, matched, mfr_data in cursor.fetchall():
                mac_prefix = addr[:8] if addr else None
                signatures.append({
                    'mac_prefix': mac_prefix,
                    'name_pattern': name.lower() if name else None,
                    'matched_as': matched,
                    'manufacturer_data_samples': mfr_data.split(',') if mfr_data else []
                })

            export_data = {
                'version': '1.0',
                'exported_at': datetime.now().isoformat(),
                'signature_count': len(signatures),
                'signatures': signatures,
                'contribution_notes': 'Submit via GitHub PR to add to main database'
            }

            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)

            logger.info(f"Exported {len(signatures)} signatures to {output_path}")
            return output_path
        finally:
            conn.close()
