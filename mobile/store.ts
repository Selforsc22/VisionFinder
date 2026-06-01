import { create } from 'zustand';

export interface DetectedDevice {
  id: string;
  name: string;
  rssi: number;
  manufacturerData: Record<number, string>;
  lastSeen: Date;
  isTheat: boolean;
  threatLevel: string;
  matchedDevice: string | null;
  hasCamera: boolean;
  hasMicrophone: boolean;
}

interface StoreState {
  devices: Map<string, DetectedDevice>;
  threats: Map<string, DetectedDevice>;
  isScanning: boolean;
  rssiThreshold: number;
  addDevice: (device: DetectedDevice) => void;
  clearDevices: () => void;
  setScanning: (scanning: boolean) => void;
  setRssiThreshold: (threshold: number) => void;
}

export const useStore = create<StoreState>((set, get) => ({
  devices: new Map(),
  threats: new Map(),
  isScanning: false,
  rssiThreshold: -75,

  addDevice: (device: DetectedDevice) => {
    set((state) => {
      const newDevices = new Map(state.devices);
      const newThreats = new Map(state.threats);

      // Update or add device
      const existing = newDevices.get(device.id);
      if (existing) {
        // Update existing device
        newDevices.set(device.id, {
          ...existing,
          rssi: device.rssi,
          lastSeen: device.lastSeen,
          name: device.name || existing.name,
        });
      } else {
        // Add new device
        newDevices.set(device.id, device);
      }

      // Track threats separately
      if (device.isTheat) {
        newThreats.set(device.id, device);
      }

      return { devices: newDevices, threats: newThreats };
    });
  },

  clearDevices: () => {
    set({ devices: new Map(), threats: new Map() });
  },

  setScanning: (scanning: boolean) => {
    set({ isScanning: scanning });
  },

  setRssiThreshold: (threshold: number) => {
    set({ rssiThreshold: threshold });
  },
}));
