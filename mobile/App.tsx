import React, { useEffect, useState, useCallback } from 'react';
import {
  StyleSheet,
  Text,
  View,
  FlatList,
  TouchableOpacity,
  Platform,
  Alert,
  Vibration,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Haptics from 'expo-haptics';
import * as Notifications from 'expo-notifications';
import { BleManager, Device, State } from 'react-native-ble-plx';
import { useStore } from './store';
import { KNOWN_DEVICES, matchDevice, ThreatLevel } from './deviceSignatures';

// Configure notifications
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
});

const bleManager = new BleManager();

export default function App() {
  const [isScanning, setIsScanning] = useState(false);
  const [bluetoothState, setBluetoothState] = useState<State>(State.Unknown);
  const { devices, threats, addDevice, clearDevices } = useStore();

  // Request permissions on mount
  useEffect(() => {
    requestPermissions();

    // Monitor Bluetooth state
    const subscription = bleManager.onStateChange((state) => {
      setBluetoothState(state);
    }, true);

    return () => {
      subscription.remove();
      bleManager.stopDeviceScan();
    };
  }, []);

  const requestPermissions = async () => {
    // Request notification permissions
    await Notifications.requestPermissionsAsync();

    // Request Bluetooth permissions (Android 12+)
    if (Platform.OS === 'android') {
      try {
        const granted = await bleManager.enable();
      } catch (error) {
        console.log('Bluetooth enable error:', error);
      }
    }
  };

  const handleThreatDetected = useCallback(async (device: Device, match: any) => {
    // Vibrate
    if (Platform.OS === 'ios') {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
    } else {
      Vibration.vibrate([0, 500, 200, 500]);
    }

    // Send notification
    await Notifications.scheduleNotificationAsync({
      content: {
        title: '⚠️ Recording Device Detected!',
        body: `${match.name} detected nearby (${device.name || 'Unknown'})`,
        sound: 'alert.wav',
        priority: Notifications.AndroidNotificationPriority.HIGH,
      },
      trigger: null,
    });
  }, []);

  const startScan = useCallback(() => {
    if (bluetoothState !== State.PoweredOn) {
      Alert.alert('Bluetooth Required', 'Please enable Bluetooth to scan for devices.');
      return;
    }

    setIsScanning(true);

    bleManager.startDeviceScan(
      null, // Scan for all devices
      { allowDuplicates: true },
      (error, device) => {
        if (error) {
          console.error('Scan error:', error);
          setIsScanning(false);
          return;
        }

        if (device) {
          // Extract manufacturer data
          const manufacturerData = device.manufacturerData
            ? parseManufacturerData(device.manufacturerData)
            : {};

          // Check for known recording devices
          const match = matchDevice(
            device.name,
            device.id,
            manufacturerData
          );

          const detectedDevice = {
            id: device.id,
            name: device.name || 'Unknown',
            rssi: device.rssi || -100,
            manufacturerData,
            lastSeen: new Date(),
            isTheat: !!match,
            threatLevel: match?.threat_level || 'none',
            matchedDevice: match?.name || null,
            hasCamera: match?.has_camera || false,
            hasMicrophone: match?.has_microphone || false,
          };

          addDevice(detectedDevice);

          // Alert if threat detected and close enough
          if (match && device.rssi && device.rssi >= -75) {
            handleThreatDetected(device, match);
          }
        }
      }
    );
  }, [bluetoothState, addDevice, handleThreatDetected]);

  const stopScan = useCallback(() => {
    bleManager.stopDeviceScan();
    setIsScanning(false);
  }, []);

  const parseManufacturerData = (data: string): Record<number, string> => {
    // Parse base64 manufacturer data
    try {
      const decoded = atob(data);
      if (decoded.length >= 2) {
        const companyId = decoded.charCodeAt(0) | (decoded.charCodeAt(1) << 8);
        return { [companyId]: data };
      }
    } catch (e) {
      console.log('Error parsing manufacturer data');
    }
    return {};
  };

  const getDistanceLabel = (rssi: number): string => {
    if (rssi >= -50) return 'Very close';
    if (rssi >= -60) return 'Close';
    if (rssi >= -70) return 'Nearby';
    if (rssi >= -80) return 'Medium';
    return 'Far';
  };

  const getThreatColor = (level: ThreatLevel): string => {
    switch (level) {
      case 'high': return '#e63757';
      case 'medium': return '#f6c343';
      case 'low': return '#28a745';
      default: return '#6c757d';
    }
  };

  const renderDevice = ({ item }: { item: any }) => (
    <View style={[
      styles.deviceCard,
      item.isTheat && styles.threatCard,
      item.threatLevel === 'high' && styles.highThreatCard,
    ]}>
      <View style={styles.deviceHeader}>
        <Text style={styles.deviceName}>{item.name}</Text>
        {item.isTheat && (
          <View style={[styles.badge, { backgroundColor: getThreatColor(item.threatLevel) }]}>
            <Text style={styles.badgeText}>
              {item.hasCamera ? '📹 CAMERA' : '🎤 MIC'}
            </Text>
          </View>
        )}
      </View>
      <Text style={styles.deviceAddress}>{item.id}</Text>
      <View style={styles.deviceDetails}>
        <Text style={styles.detailText}>
          📶 {item.rssi} dBm ({getDistanceLabel(item.rssi)})
        </Text>
        {item.matchedDevice && (
          <Text style={styles.matchText}>
            Identified: {item.matchedDevice}
          </Text>
        )}
      </View>
    </View>
  );

  const sortedDevices = [...devices.values()]
    .sort((a, b) => {
      // Threats first, then by RSSI
      if (a.isTheat && !b.isTheat) return -1;
      if (!a.isTheat && b.isTheat) return 1;
      return b.rssi - a.rssi;
    });

  const threatCount = [...devices.values()].filter(d => d.isTheat).length;

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />

      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>VisionFinder</Text>
        <Text style={styles.subtitle}>Recording Device Scanner</Text>
      </View>

      {/* Stats */}
      <View style={styles.statsRow}>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>{devices.size}</Text>
          <Text style={styles.statLabel}>Devices</Text>
        </View>
        <View style={[styles.statCard, styles.threatStatCard]}>
          <Text style={[styles.statValue, styles.threatStatValue]}>{threatCount}</Text>
          <Text style={styles.statLabel}>Threats</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>
            {bluetoothState === State.PoweredOn ? '✓' : '✗'}
          </Text>
          <Text style={styles.statLabel}>Bluetooth</Text>
        </View>
      </View>

      {/* Controls */}
      <View style={styles.controls}>
        <TouchableOpacity
          style={[styles.button, isScanning && styles.buttonActive]}
          onPress={isScanning ? stopScan : startScan}
        >
          <Text style={styles.buttonText}>
            {isScanning ? '⏹ Stop Scanning' : '▶ Start Scanning'}
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, styles.buttonSecondary]}
          onPress={clearDevices}
        >
          <Text style={styles.buttonText}>Clear</Text>
        </TouchableOpacity>
      </View>

      {/* Scanning indicator */}
      {isScanning && (
        <View style={styles.scanningIndicator}>
          <Text style={styles.scanningText}>🔍 Scanning for devices...</Text>
        </View>
      )}

      {/* Device list */}
      <FlatList
        data={sortedDevices}
        renderItem={renderDevice}
        keyExtractor={(item) => item.id}
        style={styles.deviceList}
        contentContainerStyle={styles.deviceListContent}
        ListEmptyComponent={
          <View style={styles.emptyState}>
            <Text style={styles.emptyText}>
              {isScanning ? 'Scanning...' : 'Tap "Start Scanning" to detect nearby devices'}
            </Text>
          </View>
        }
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f0f1a',
  },
  header: {
    paddingHorizontal: 20,
    paddingVertical: 15,
    alignItems: 'center',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#4a9eff',
  },
  subtitle: {
    fontSize: 14,
    color: '#a0a0a0',
    marginTop: 4,
  },
  statsRow: {
    flexDirection: 'row',
    paddingHorizontal: 15,
    gap: 10,
  },
  statCard: {
    flex: 1,
    backgroundColor: '#1a1a2e',
    borderRadius: 12,
    padding: 15,
    alignItems: 'center',
  },
  threatStatCard: {
    borderColor: '#e63757',
    borderWidth: 1,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#4a9eff',
  },
  threatStatValue: {
    color: '#e63757',
  },
  statLabel: {
    fontSize: 12,
    color: '#a0a0a0',
    marginTop: 4,
  },
  controls: {
    flexDirection: 'row',
    paddingHorizontal: 15,
    paddingVertical: 15,
    gap: 10,
  },
  button: {
    flex: 1,
    backgroundColor: '#4a9eff',
    borderRadius: 10,
    padding: 15,
    alignItems: 'center',
  },
  buttonActive: {
    backgroundColor: '#e63757',
  },
  buttonSecondary: {
    flex: 0.4,
    backgroundColor: '#2d2d4a',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  scanningIndicator: {
    backgroundColor: 'rgba(74, 158, 255, 0.1)',
    padding: 10,
    marginHorizontal: 15,
    borderRadius: 8,
  },
  scanningText: {
    color: '#4a9eff',
    textAlign: 'center',
  },
  deviceList: {
    flex: 1,
  },
  deviceListContent: {
    padding: 15,
    gap: 10,
  },
  deviceCard: {
    backgroundColor: '#1a1a2e',
    borderRadius: 12,
    padding: 15,
    borderLeftWidth: 4,
    borderLeftColor: '#2d2d4a',
  },
  threatCard: {
    borderLeftColor: '#f6c343',
  },
  highThreatCard: {
    borderLeftColor: '#e63757',
    backgroundColor: 'rgba(230, 55, 87, 0.1)',
  },
  deviceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  deviceName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#e0e0e0',
    flex: 1,
  },
  deviceAddress: {
    fontSize: 12,
    color: '#6c757d',
    marginTop: 4,
  },
  deviceDetails: {
    marginTop: 10,
  },
  detailText: {
    fontSize: 13,
    color: '#a0a0a0',
  },
  matchText: {
    fontSize: 13,
    color: '#e63757',
    fontWeight: '500',
    marginTop: 5,
  },
  badge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  badgeText: {
    color: '#fff',
    fontSize: 11,
    fontWeight: 'bold',
  },
  emptyState: {
    padding: 40,
    alignItems: 'center',
  },
  emptyText: {
    color: '#6c757d',
    textAlign: 'center',
  },
});
