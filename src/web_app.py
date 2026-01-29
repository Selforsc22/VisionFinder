"""
Flask Web Application for Bluetooth Scanner
Provides a web UI for monitoring and managing the scanner
"""

import asyncio
import json
import logging
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit

from .scanner import BluetoothScanner, DetectedDevice, RecordingDeviceDatabase
from .device_logger import DeviceLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__,
            template_folder=str(Path(__file__).parent.parent / "templates"),
            static_folder=str(Path(__file__).parent.parent / "static"))
app.config['SECRET_KEY'] = 'bluetooth-scanner-secret-key-change-in-production'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Global scanner and logger instances
scanner: BluetoothScanner = None
device_logger: DeviceLogger = None
scan_thread: threading.Thread = None
scan_loop: asyncio.AbstractEventLoop = None


def init_scanner():
    """Initialize scanner and logger"""
    global scanner, device_logger
    device_db = RecordingDeviceDatabase()
    scanner = BluetoothScanner(device_db)
    device_logger = DeviceLogger()

    def on_device_detected(device: DetectedDevice):
        device_logger.log_device(device)
        socketio.emit('device_detected', device.to_dict())

    def on_threat_detected(device: DetectedDevice):
        device_logger.log_threat_alert(device)
        socketio.emit('threat_alert', device.to_dict())
        logger.warning(f"THREAT ALERT: {device.matched_signature.name if device.matched_signature else 'Unknown'} detected!")

    scanner.on_device_detected = on_device_detected
    scanner.on_threat_detected = on_threat_detected


def run_async_scanner():
    """Run the async scanner in a separate thread"""
    global scan_loop
    scan_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(scan_loop)

    def callback(device):
        if device:
            socketio.emit('device_update', device.to_dict())

    try:
        scan_loop.run_until_complete(scanner.start_continuous_scan(callback))
    except asyncio.CancelledError:
        pass
    finally:
        scan_loop.close()


# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/status')
def get_status():
    """Get scanner status"""
    return jsonify({
        'scanning': scanner.scanning if scanner else False,
        'device_count': len(scanner.detected_devices) if scanner else 0,
        'threat_count': len(scanner.get_threats()) if scanner else 0
    })


@app.route('/api/devices')
def get_devices():
    """Get all detected devices"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    devices = [d.to_dict() for d in scanner.get_all_devices()]
    return jsonify({'devices': devices})


@app.route('/api/threats')
def get_threats():
    """Get detected threats only"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    threats = [d.to_dict() for d in scanner.get_threats()]
    return jsonify({'threats': threats})


@app.route('/api/history')
def get_history():
    """Get device history from logs"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    threats_only = request.args.get('threats_only', 'false').lower() == 'true'
    devices = device_logger.get_all_devices(threats_only=threats_only)
    return jsonify({'devices': devices})


@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    limit = request.args.get('limit', 50, type=int)
    alerts = device_logger.get_recent_alerts(limit=limit)
    return jsonify({'alerts': alerts})


@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    device_logger.acknowledge_alert(alert_id)
    return jsonify({'success': True})


@app.route('/api/statistics')
def get_statistics():
    """Get scanning statistics"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    stats = device_logger.get_statistics()
    return jsonify(stats)


@app.route('/api/signatures')
def get_signatures():
    """Get known device signatures"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    signatures = []
    for sig in scanner.device_db.signatures:
        signatures.append({
            'id': sig.id,
            'name': sig.name,
            'manufacturer': sig.manufacturer,
            'type': sig.device_type,
            'has_camera': sig.has_camera,
            'has_microphone': sig.has_microphone,
            'threat_level': sig.threat_level,
            'notes': sig.notes
        })

    return jsonify({'signatures': signatures, 'threat_levels': scanner.device_db.threat_levels})


@app.route('/api/export/csv')
def export_csv():
    """Export devices to CSV"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    path = device_logger.export_to_csv()
    return jsonify({'success': True, 'path': str(path)})


# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected")
    emit('status', {
        'scanning': scanner.scanning if scanner else False,
        'message': 'Connected to Bluetooth Scanner'
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")


@socketio.on('start_scan')
def handle_start_scan():
    """Start scanning"""
    global scan_thread

    if not scanner:
        init_scanner()

    if scanner.scanning:
        emit('error', {'message': 'Scanner already running'})
        return

    scan_thread = threading.Thread(target=run_async_scanner, daemon=True)
    scan_thread.start()

    emit('scan_started', {'message': 'Scanning started'})
    socketio.emit('status', {'scanning': True})
    logger.info("Scanning started via WebSocket")


@socketio.on('stop_scan')
def handle_stop_scan():
    """Stop scanning"""
    if scanner:
        scanner.stop_scanning()
        emit('scan_stopped', {'message': 'Scanning stopped'})
        socketio.emit('status', {'scanning': False})
        logger.info("Scanning stopped via WebSocket")


@socketio.on('clear_devices')
def handle_clear_devices():
    """Clear detected devices"""
    if scanner:
        scanner.clear_devices()
        emit('devices_cleared', {'message': 'Devices cleared'})


@socketio.on('get_devices')
def handle_get_devices():
    """Request current device list"""
    if scanner:
        devices = [d.to_dict() for d in scanner.get_all_devices()]
        emit('device_list', {'devices': devices})


def run_server(host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
    """Run the web server"""
    init_scanner()
    logger.info(f"Starting web server on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_server(debug=True)
