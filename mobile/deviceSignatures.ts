/**
 * Known recording device signatures for detection
 * Based on verified BLE manufacturer IDs from Bluetooth SIG
 *
 * Sources:
 * - Nearby Glasses app (Yves Jeanrenaud)
 * - Bluetooth SIG assigned numbers database
 * - Community contributions
 */

export type ThreatLevel = 'high' | 'medium' | 'low' | 'none';

export interface DeviceSignature {
  id: string;
  name: string;
  manufacturer: string;
  type: string;
  has_camera: boolean;
  has_microphone: boolean;
  threat_level: ThreatLevel;
  name_patterns: string[];
  manufacturer_prefixes: string[];
  ble_manufacturer_ids: number[];
  service_uuids: string[];
  false_positives?: string[];
}

/**
 * BLE Manufacturer IDs are assigned by Bluetooth SIG.
 * They are mandatory, standardized, and cannot be spoofed without breaking compliance.
 * This makes them the most reliable detection method.
 */
export const BLE_MANUFACTURER_IDS = {
  META_PLATFORMS: 0x01ab, // 427 - Meta Platforms, Inc.
  META_TECHNOLOGIES: 0x058e, // 1422 - Meta Platforms Technologies, LLC
  LUXOTTICA: 0x0d53, // 3411 - Luxottica Group (Ray-Ban)
  SNAP: 0x03c2, // 962 - Snap Inc. (Spectacles)
  AMAZON: 0x00ab, // 171 - Amazon
  GOOGLE: 0x00e0, // 224 - Google
  GOPRO: 0x028e, // 654 - GoPro
  DJI: 0x02c2, // 706 - DJI
  VUZIX: 0x0485, // 1157 - Vuzix
  XIAOMI: 0x0157, // 343 - Xiaomi
  HUAWEI: 0x027d, // 637 - Huawei
  BOSE: 0x009e, // 158 - Bose
  APPLE: 0x004c, // 76 - Apple (for filtering)
  SAMSUNG: 0x0075, // 117 - Samsung (for filtering)
} as const;

/**
 * Known recording devices database
 * Detection priority: manufacturer_id > mac_prefix > name_pattern > service_uuid
 */
export const KNOWN_DEVICES: DeviceSignature[] = [
  {
    id: 'meta_smart_glasses',
    name: 'Meta Smart Glasses (Ray-Ban/Oakley)',
    manufacturer: 'Meta/Luxottica',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: [
      'ray-ban',
      'rayban',
      'meta',
      'oakley',
      'wayfarer',
    ],
    manufacturer_prefixes: ['E4:F0:42', '9C:B6:D0', '64:A2:F9', '3C:28:6D'],
    ble_manufacturer_ids: [
      BLE_MANUFACTURER_IDS.META_PLATFORMS,
      BLE_MANUFACTURER_IDS.META_TECHNOLOGIES,
      BLE_MANUFACTURER_IDS.LUXOTTICA,
    ],
    service_uuids: ['0000fe03-0000-1000-8000-00805f9b34fb'],
    false_positives: ['Meta Quest VR headsets share these manufacturer IDs'],
  },
  {
    id: 'snapchat_spectacles',
    name: 'Snapchat Spectacles',
    manufacturer: 'Snap Inc.',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['spectacles', 'snap'],
    manufacturer_prefixes: ['58:D5:0A'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.SNAP],
    service_uuids: [],
  },
  {
    id: 'amazon_echo_frames',
    name: 'Amazon Echo Frames',
    manufacturer: 'Amazon',
    type: 'smart_glasses',
    has_camera: false,
    has_microphone: true,
    threat_level: 'medium',
    name_patterns: ['echo frames', 'amazon frames', 'alexa frames', 'carrera smart'],
    manufacturer_prefixes: ['FC:65:DE', '68:54:FD', '44:07:0B'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.AMAZON],
    service_uuids: [],
  },
  {
    id: 'google_glass',
    name: 'Google Glass',
    manufacturer: 'Google',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['glass', 'google glass', 'glass enterprise'],
    manufacturer_prefixes: ['F8:8F:CA', '54:60:09', 'F4:F5:D8'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.GOOGLE],
    service_uuids: [],
  },
  {
    id: 'gopro',
    name: 'GoPro Camera',
    manufacturer: 'GoPro',
    type: 'action_camera',
    has_camera: true,
    has_microphone: true,
    threat_level: 'medium',
    name_patterns: ['gopro', 'hero', 'gp:'],
    manufacturer_prefixes: ['D4:D9:19', '24:A0:74', 'C4:CB:6B'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.GOPRO],
    service_uuids: [
      '0000fea6-0000-1000-8000-00805f9b34fb',
      'b5f90001-aa8d-11e3-9046-0002a5d5c51b',
    ],
  },
  {
    id: 'dji_action',
    name: 'DJI Action/Osmo Camera',
    manufacturer: 'DJI',
    type: 'action_camera',
    has_camera: true,
    has_microphone: true,
    threat_level: 'medium',
    name_patterns: ['dji', 'osmo', 'action', 'pocket'],
    manufacturer_prefixes: ['60:60:1F', '34:D2:62'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.DJI],
    service_uuids: [],
  },
  {
    id: 'vuzix_blade',
    name: 'Vuzix Blade/Shield',
    manufacturer: 'Vuzix',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['vuzix', 'blade', 'shield'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.VUZIX],
    service_uuids: [],
  },
  {
    id: 'xiaomi_smart_glasses',
    name: 'Xiaomi Smart Glasses',
    manufacturer: 'Xiaomi',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['xiaomi glass', 'mi glass'],
    manufacturer_prefixes: ['64:CC:2E', '78:11:DC'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.XIAOMI],
    service_uuids: [],
  },
  {
    id: 'huawei_eyewear',
    name: 'Huawei Eyewear',
    manufacturer: 'Huawei',
    type: 'smart_glasses',
    has_camera: false,
    has_microphone: true,
    threat_level: 'medium',
    name_patterns: ['huawei eyewear', 'huawei-eye'],
    manufacturer_prefixes: ['48:DB:50', '94:E2:3C'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.HUAWEI],
    service_uuids: [],
  },
  {
    id: 'insta360_go',
    name: 'Insta360 GO',
    manufacturer: 'Insta360',
    type: 'wearable_camera',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['insta360', 'go 3', 'go 2', 'go3'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
    service_uuids: ['0000ffe0-0000-1000-8000-00805f9b34fb'],
  },
  {
    id: 'brilliant_monocle',
    name: 'Brilliant Monocle/Frame',
    manufacturer: 'Brilliant Labs',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['monocle', 'brilliant', 'frame'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
    service_uuids: ['7a230001-5475-a6a4-654c-8431b6ad49c4'],
  },
  {
    id: 'bose_frames',
    name: 'Bose Frames',
    manufacturer: 'Bose',
    type: 'smart_glasses',
    has_camera: false,
    has_microphone: true,
    threat_level: 'low',
    name_patterns: ['bose frames'],
    manufacturer_prefixes: ['04:52:C7', '28:11:A5'],
    ble_manufacturer_ids: [BLE_MANUFACTURER_IDS.BOSE],
    service_uuids: [],
  },
  {
    id: 'tcl_rayneo',
    name: 'TCL RayNeo/Xreal',
    manufacturer: 'TCL/Xreal',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['rayneo', 'nreal', 'xreal', 'air 2'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
    service_uuids: [],
  },
  {
    id: 'even_realities_g1',
    name: 'Even Realities G1',
    manufacturer: 'Even Realities',
    type: 'smart_glasses',
    has_camera: false,
    has_microphone: true,
    threat_level: 'medium',
    name_patterns: ['even realities', 'g1', 'er-g1'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
    service_uuids: [],
  },
];

/**
 * Service UUIDs that may indicate recording capability
 */
export const SUSPICIOUS_SERVICE_UUIDS = {
  CAMERA_CONTROL: '0000ffe0-0000-1000-8000-00805f9b34fb',
  GOPRO_SERVICE: '0000fea6-0000-1000-8000-00805f9b34fb',
  A2DP_SOURCE: '0000110a-0000-1000-8000-00805f9b34fb',
  A2DP_SINK: '0000110b-0000-1000-8000-00805f9b34fb',
  HANDSFREE: '0000111e-0000-1000-8000-00805f9b34fb',
};

/**
 * Match a detected device against known signatures
 * Returns the matching signature or null
 *
 * Detection priority (most reliable first):
 * 1. BLE Manufacturer ID
 * 2. MAC address prefix (OUI)
 * 3. BLE Service UUIDs
 * 4. Device name patterns
 */
export function matchDevice(
  name: string | null,
  address: string,
  manufacturerData: Record<number, string>,
  serviceUuids?: string[]
): DeviceSignature | null {
  const addressUpper = address.toUpperCase();
  const nameLower = name?.toLowerCase() || '';
  const uuidsLower = (serviceUuids || []).map((u) => u.toLowerCase());

  for (const sig of KNOWN_DEVICES) {
    // Priority 1: Check BLE manufacturer ID (most reliable)
    for (const mfrId of Object.keys(manufacturerData)) {
      if (sig.ble_manufacturer_ids.includes(parseInt(mfrId))) {
        return sig;
      }
    }

    // Priority 2: Check MAC address prefix (OUI)
    for (const prefix of sig.manufacturer_prefixes) {
      if (addressUpper.startsWith(prefix.toUpperCase())) {
        return sig;
      }
    }

    // Priority 3: Check service UUIDs
    for (const uuid of sig.service_uuids) {
      if (uuidsLower.includes(uuid.toLowerCase())) {
        return sig;
      }
    }

    // Priority 4: Check device name patterns
    if (nameLower) {
      for (const pattern of sig.name_patterns) {
        if (nameLower.includes(pattern.toLowerCase())) {
          return sig;
        }
      }
    }
  }

  return null;
}

/**
 * Get threat level color for UI
 */
export function getThreatColor(level: ThreatLevel): string {
  switch (level) {
    case 'high':
      return '#e63757';
    case 'medium':
      return '#f6c343';
    case 'low':
      return '#28a745';
    default:
      return '#6c757d';
  }
}

/**
 * Check if a manufacturer ID belongs to a common non-threat device
 * Used to filter out noise from phones, headphones, etc.
 */
export function isCommonDevice(manufacturerId: number): boolean {
  const commonIds = [
    BLE_MANUFACTURER_IDS.APPLE,
    BLE_MANUFACTURER_IDS.SAMSUNG,
    0x0006, // Microsoft
    0x000f, // Broadcom
    0x001d, // Qualcomm
  ];
  return commonIds.includes(manufacturerId);
}

/**
 * Format manufacturer ID as hex string
 */
export function formatManufacturerId(id: number): string {
  return `0x${id.toString(16).padStart(4, '0').toUpperCase()}`;
}
