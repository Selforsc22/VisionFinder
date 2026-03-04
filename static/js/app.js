/**
 * Bluetooth Device Scanner - Frontend JavaScript
 */

// Global state
let socket = null;
let devices = new Map();
let threats = new Map();
let isScanning = false;
let alertSound = null;
let alertsEnabled = true;

// DOM Elements
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const startBtn = document.getElementById('start-btn');
const stopBtn = document.getElementById('stop-btn');
const clearBtn = document.getElementById('clear-btn');
const alertBanner = document.getElementById('alert-banner');
const alertMessage = document.getElementById('alert-message');

// Statistics elements
const totalDevicesEl = document.getElementById('total-devices');
const threatCountEl = document.getElementById('threat-count');
const highThreatCountEl = document.getElementById('high-threat-count');
const mediumThreatCountEl = document.getElementById('medium-threat-count');

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeSocket();
    loadSignatures();
    loadAlertHistory();
    alertSound = document.getElementById('alert-sound');
});

/**
 * Initialize WebSocket connection
 */
function initializeSocket() {
    socket = io();

    socket.on('connect', () => {
        console.log('Connected to server');
        updateStatus('connected', 'Connected');
        socket.emit('get_devices');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
        updateStatus('disconnected', 'Disconnected');
    });

    socket.on('status', (data) => {
        isScanning = data.scanning;
        updateScanButtons();
        if (data.scanning) {
            updateStatus('scanning', 'Scanning...');
        }
    });

    socket.on('scan_started', (data) => {
        isScanning = true;
        updateScanButtons();
        updateStatus('scanning', 'Scanning...');
        showNotification('Scanning started');
    });

    socket.on('scan_stopped', (data) => {
        isScanning = false;
        updateScanButtons();
        updateStatus('connected', 'Connected - Idle');
        showNotification('Scanning stopped');
    });

    socket.on('device_detected', (device) => {
        addDevice(device);
        updateStatistics();
    });

    socket.on('device_update', (device) => {
        addDevice(device, false);
        updateStatistics();
    });

    socket.on('device_list', (data) => {
        data.devices.forEach(device => addDevice(device, false));
        updateStatistics();
    });

    socket.on('threat_alert', (device) => {
        handleThreatAlert(device);
    });

    socket.on('devices_cleared', () => {
        devices.clear();
        threats.clear();
        renderDeviceList();
        renderThreatList();
        updateStatistics();
        showNotification('Devices cleared');
    });

    socket.on('error', (data) => {
        console.error('Socket error:', data.message);
        showNotification(data.message, 'error');
    });
}

/**
 * Update connection status indicator
 */
function updateStatus(state, text) {
    statusDot.className = 'status-dot ' + state;
    statusText.textContent = text;
}

/**
 * Update scan button states
 */
function updateScanButtons() {
    startBtn.disabled = isScanning;
    stopBtn.disabled = !isScanning;
}

/**
 * Start scanning
 */
function startScan() {
    if (socket) {
        socket.emit('start_scan');
    }
}

/**
 * Stop scanning
 */
function stopScan() {
    if (socket) {
        socket.emit('stop_scan');
    }
}

/**
 * Clear all detected devices
 */
function clearDevices() {
    if (socket) {
        socket.emit('clear_devices');
    }
}

/**
 * Add or update a device
 */
function addDevice(device, isNew = true) {
    const existingDevice = devices.get(device.address);
    devices.set(device.address, device);

    if (device.is_potential_threat) {
        threats.set(device.address, device);
    }

    renderDeviceList();
    renderThreatList();
}

/**
 * Render the device list
 */
function renderDeviceList() {
    const container = document.getElementById('devices-list');

    if (devices.size === 0) {
        container.innerHTML = '<div class="empty-state">No devices detected</div>';
        return;
    }

    const sortedDevices = Array.from(devices.values())
        .sort((a, b) => b.rssi - a.rssi);

    container.innerHTML = sortedDevices.map(device => createDeviceCard(device)).join('');
}

/**
 * Render the threat list
 */
function renderThreatList() {
    const container = document.getElementById('threats-list');

    if (threats.size === 0) {
        container.innerHTML = '<div class="empty-state">No threats detected</div>';
        return;
    }

    const sortedThreats = Array.from(threats.values())
        .sort((a, b) => {
            // Sort by threat level (high first) then by RSSI
            const levelOrder = { 'high': 0, 'medium': 1, 'low': 2 };
            if (levelOrder[a.threat_level] !== levelOrder[b.threat_level]) {
                return levelOrder[a.threat_level] - levelOrder[b.threat_level];
            }
            return b.rssi - a.rssi;
        });

    container.innerHTML = sortedThreats.map(device => createDeviceCard(device, true)).join('');
}

/**
 * Create a device card HTML
 */
function createDeviceCard(device, isThreat = false) {
    const threatClass = device.is_potential_threat ? `threat threat-${device.threat_level}` : '';
    const rssiIndicator = createRSSIIndicator(device.rssi);

    let badges = '';
    if (device.is_potential_threat) {
        badges += `<span class="device-badge badge-threat">${device.threat_level} RISK</span>`;
    }
    if (device.has_camera) {
        badges += '<span class="device-badge badge-camera">CAMERA</span>';
    }
    if (device.has_microphone && !device.has_camera) {
        badges += '<span class="device-badge badge-mic">MIC</span>';
    }

    let matchInfo = '';
    if (device.matched_device) {
        matchInfo = `
            <div class="device-match">
                <strong>Identified as:</strong> ${device.matched_device}
                ${device.matched_device_type ? `<span>(${device.matched_device_type})</span>` : ''}
            </div>
        `;
    }

    // Show manufacturer IDs if present (key for Meta glasses detection)
    let mfrInfo = '';
    if (device.manufacturer_ids_hex && device.manufacturer_ids_hex.length > 0) {
        mfrInfo = `<span title="BLE Manufacturer ID">MFR: ${device.manufacturer_ids_hex.join(', ')}</span>`;
    }

    // Show estimated distance
    const distance = device.rssi_distance || '';

    return `
        <div class="device-card ${threatClass}" data-address="${device.address}">
            <div class="device-header">
                <div>
                    <div class="device-name">${escapeHtml(device.name)}</div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary);">${device.address}</div>
                </div>
                <div style="text-align: right;">
                    ${badges}
                </div>
            </div>
            <div class="device-details">
                <span>${rssiIndicator} ${device.rssi} dBm</span>
                <span>${distance}</span>
                <span>Last seen: ${formatTime(device.last_seen)}</span>
                ${mfrInfo}
            </div>
            ${matchInfo}
        </div>
    `;
}

/**
 * Create RSSI indicator bars
 */
function createRSSIIndicator(rssi) {
    const bars = 5;
    const strength = Math.min(Math.max(Math.floor((rssi + 100) / 15), 0), bars);

    let html = '<span class="rssi-indicator">';
    for (let i = 0; i < bars; i++) {
        const height = 4 + (i * 3);
        const active = i < strength ? 'active' : '';
        html += `<span class="rssi-bar ${active}" style="height: ${height}px;"></span>`;
    }
    html += '</span>';
    return html;
}

/**
 * Handle threat alert
 */
function handleThreatAlert(device) {
    // Add to threats map
    threats.set(device.address, device);

    // Show alert banner
    alertBanner.classList.remove('hidden');
    alertMessage.textContent = `${device.matched_device || 'Recording device'} detected nearby! (${device.address})`;

    // Play alert sound
    if (alertsEnabled && alertSound) {
        alertSound.play().catch(e => console.log('Audio play failed:', e));
    }

    // Add to alerts history
    addAlertToHistory(device);

    // Update UI
    renderThreatList();
    updateStatistics();

    // Browser notification if permitted
    if (Notification.permission === 'granted') {
        new Notification('Recording Device Detected!', {
            body: `${device.matched_device || 'Unknown device'} at ${device.address}`,
            icon: '/static/img/alert-icon.png'
        });
    }
}

/**
 * Dismiss alert banner
 */
function dismissAlert() {
    alertBanner.classList.add('hidden');
}

/**
 * Add alert to history UI
 */
function addAlertToHistory(device) {
    const container = document.getElementById('alerts-list');
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) {
        container.innerHTML = '';
    }

    const alertItem = document.createElement('div');
    alertItem.className = 'alert-item';
    alertItem.innerHTML = `
        <div class="alert-info">
            <div class="alert-device">${escapeHtml(device.matched_device || device.name)}</div>
            <div class="alert-time">${device.address} - ${new Date().toLocaleString()}</div>
        </div>
        <div class="alert-actions">
            <button onclick="this.parentElement.parentElement.classList.add('acknowledged')">
                Acknowledge
            </button>
        </div>
    `;
    container.insertBefore(alertItem, container.firstChild);
}

/**
 * Update statistics display
 */
function updateStatistics() {
    totalDevicesEl.textContent = devices.size;
    threatCountEl.textContent = threats.size;

    let highCount = 0;
    let mediumCount = 0;

    threats.forEach(device => {
        if (device.threat_level === 'high') highCount++;
        else if (device.threat_level === 'medium') mediumCount++;
    });

    highThreatCountEl.textContent = highCount;
    mediumThreatCountEl.textContent = mediumCount;
}

/**
 * Load known device signatures
 */
async function loadSignatures() {
    try {
        const response = await fetch('/api/signatures');
        const data = await response.json();
        renderSignatures(data.signatures);
    } catch (error) {
        console.error('Failed to load signatures:', error);
    }
}

/**
 * Render signatures list
 */
function renderSignatures(signatures) {
    const container = document.getElementById('signatures-list');

    container.innerHTML = signatures.map(sig => `
        <div class="signature-card">
            <h4>${escapeHtml(sig.name)}</h4>
            <div class="manufacturer">${escapeHtml(sig.manufacturer)}</div>
            <div class="signature-badges">
                <span class="badge" style="background: ${getThreatColor(sig.threat_level)}; color: white;">
                    ${sig.threat_level.toUpperCase()}
                </span>
                ${sig.has_camera ? '<span class="badge badge-camera">CAMERA</span>' : ''}
                ${sig.has_microphone ? '<span class="badge badge-mic">MIC</span>' : ''}
            </div>
            <p style="margin-top: 10px; font-size: 0.85rem; color: var(--text-secondary);">
                ${escapeHtml(sig.notes)}
            </p>
        </div>
    `).join('');
}

/**
 * Get threat level color
 */
function getThreatColor(level) {
    const colors = {
        'high': '#e63757',
        'medium': '#f6c343',
        'low': '#00d97e'
    };
    return colors[level] || '#6c757d';
}

/**
 * Load alert history from API
 */
async function loadAlertHistory() {
    try {
        const response = await fetch('/api/alerts');
        const data = await response.json();
        renderAlertHistory(data.alerts);
    } catch (error) {
        console.error('Failed to load alert history:', error);
    }
}

/**
 * Render alert history
 */
function renderAlertHistory(alerts) {
    const container = document.getElementById('alerts-list');

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="empty-state">No alerts recorded</div>';
        return;
    }

    container.innerHTML = alerts.map(alert => `
        <div class="alert-item ${alert.acknowledged ? 'acknowledged' : ''}">
            <div class="alert-info">
                <div class="alert-device">${escapeHtml(alert.matched_device || alert.device_name || 'Unknown')}</div>
                <div class="alert-time">${alert.device_address} - ${formatDateTime(alert.timestamp)}</div>
            </div>
            <div class="alert-actions">
                ${!alert.acknowledged ? `
                    <button onclick="acknowledgeAlert(${alert.id}, this)">Acknowledge</button>
                ` : ''}
            </div>
        </div>
    `).join('');
}

/**
 * Acknowledge an alert
 */
async function acknowledgeAlert(alertId, button) {
    try {
        await fetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
        button.parentElement.parentElement.classList.add('acknowledged');
        button.remove();
    } catch (error) {
        console.error('Failed to acknowledge alert:', error);
    }
}

/**
 * Toggle collapsible section
 */
function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    section.classList.toggle('collapsed');

    // Toggle icon rotation
    const header = section.previousElementSibling;
    if (header) {
        const icon = header.querySelector('.toggle-icon');
        if (icon) {
            section.classList.contains('collapsed')
                ? icon.style.transform = ''
                : icon.style.transform = 'rotate(180deg)';
        }
    }
}

/**
 * Handle file import
 */
function handleFileImport(event) {
    const file = event.target.files[0];
    if (!file) return;

    document.getElementById('file-name').textContent = file.name;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const content = e.target.result;
            const parsed = parseLogFile(content, file.name);

            if (parsed.devices && parsed.devices.length > 0) {
                parsed.devices.forEach(device => {
                    addDevice(device, true);
                });
                updateStatistics();
                showNotification(`Imported ${parsed.devices.length} devices from ${file.name}`);
            } else {
                showNotification('No devices found in file', 'warning');
            }
        } catch (error) {
            console.error('Error parsing file:', error);
            showNotification('Error parsing file: ' + error.message, 'error');
        }
    };
    reader.readAsText(file);
}

/**
 * Parse log file based on format
 */
function parseLogFile(content, filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const devices = [];

    if (ext === 'json') {
        const data = JSON.parse(content);
        // Handle various JSON formats
        if (Array.isArray(data)) {
            data.forEach(item => {
                devices.push(normalizeDevice(item));
            });
        } else if (data.devices) {
            data.devices.forEach(item => {
                devices.push(normalizeDevice(item));
            });
        } else if (data.entries) {
            data.entries.forEach(entry => {
                devices.push(normalizeDevice(entry.device || entry));
            });
        }
    } else if (ext === 'csv') {
        const lines = content.trim().split('\n');
        const headers = lines[0].split(',').map(h => h.trim().toLowerCase());

        for (let i = 1; i < lines.length; i++) {
            const values = lines[i].split(',');
            const device = {};
            headers.forEach((h, idx) => {
                device[h] = values[idx]?.trim();
            });
            devices.push(normalizeDevice(device));
        }
    } else {
        // Plain text - assume one device per line
        const lines = content.trim().split('\n');
        lines.forEach(line => {
            const match = line.match(/([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/);
            if (match) {
                devices.push({
                    address: match[0].toUpperCase(),
                    name: line.replace(match[0], '').trim() || 'Unknown',
                    rssi: -70,
                    first_seen: new Date().toISOString(),
                    last_seen: new Date().toISOString(),
                    is_potential_threat: false,
                    threat_level: 'unknown'
                });
            }
        });
    }

    return { devices };
}

/**
 * Normalize device data from various formats
 */
function normalizeDevice(data) {
    return {
        address: data.address || data.mac || data.mac_address || 'Unknown',
        name: data.name || data.device_name || data.local_name || 'Unknown',
        rssi: parseInt(data.rssi) || -70,
        first_seen: data.first_seen || data.firstSeen || new Date().toISOString(),
        last_seen: data.last_seen || data.lastSeen || new Date().toISOString(),
        is_potential_threat: data.is_potential_threat || data.is_threat || false,
        threat_level: data.threat_level || 'unknown',
        matched_device: data.matched_device || null,
        has_camera: data.has_camera || false,
        has_microphone: data.has_microphone || false
    };
}

/**
 * Show notification toast
 */
function showNotification(message, type = 'info') {
    console.log(`[${type}] ${message}`);
    // Could implement a toast notification system here
}

/**
 * Format time for display
 */
function formatTime(isoString) {
    if (!isoString) return 'Unknown';
    const date = new Date(isoString);
    return date.toLocaleTimeString();
}

/**
 * Format datetime for display
 */
function formatDateTime(isoString) {
    if (!isoString) return 'Unknown';
    const date = new Date(isoString);
    return date.toLocaleString();
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return 'Unknown';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Request notification permission on page load
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}
