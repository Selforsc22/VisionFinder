/**
 * Known recording device signatures for detection
 * Based on BLE manufacturer IDs and device name patterns
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
}

/**
 * Known recording devices database
 * BLE manufacturer IDs are the most reliable detection method
 */
export const KNOWN_DEVICES: DeviceSignature[] = [
  {
    id: 'meta_smart_glasses',
    name: 'Meta Smart Glasses (Ray-Ban/Oakley)',
    manufacturer: 'Meta/Luxottica/Woan Technology',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: [
      'ray-ban stories',
      'ray-ban meta',
      'ray-ban | meta',
      'rayban stories',
      'rb stories',
      'meta smart',
      'meta ray-ban',
      'woan',
      'oakley',
    ],
    manufacturer_prefixes: ['E4:F0:42', '9C:B6:D0', '64:A2:F9'],
    // Key manufacturer IDs for Meta glasses detection:
    // 0x01AB (427) = Meta Platforms, Inc.
    // 0x058E (1422) = Meta Platforms Technologies, LLC
    // 0x0969 (2409) = Woan Technology Shenzhen (glasses OEM)
    // 0x0D53 (3411) = Luxottica Group S.p.A
    ble_manufacturer_ids: [427, 1422, 2409, 3411],
  },
  {
    id: 'snapchat_spectacles',
    name: 'Snapchat Spectacles',
    manufacturer: 'Snap Inc.',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['spectacles', 'snap spectacles'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
  },
  {
    id: 'amazon_echo_frames',
    name: 'Amazon Echo Frames',
    manufacturer: 'Amazon',
    type: 'smart_glasses',
    has_camera: false,
    has_microphone: true,
    threat_level: 'medium',
    name_patterns: ['echo frames', 'amazon frames', 'alexa frames'],
    manufacturer_prefixes: ['FC:65:DE', '68:54:FD'],
    ble_manufacturer_ids: [171], // Amazon 0x00AB
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
    manufacturer_prefixes: ['F8:8F:CA', '54:60:09'],
    ble_manufacturer_ids: [224], // Google 0x00E0
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
    manufacturer_prefixes: ['D4:D9:19', '24:A0:74'],
    ble_manufacturer_ids: [654], // GoPro 0x028E
  },
  {
    id: 'vuzix_blade',
    name: 'Vuzix Blade',
    manufacturer: 'Vuzix',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['vuzix', 'blade'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
  },
  {
    id: 'insta360_go',
    name: 'Insta360 GO',
    manufacturer: 'Insta360',
    type: 'wearable_camera',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['insta360', 'go 3', 'go 2'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
  },
  {
    id: 'dji_action',
    name: 'DJI Action Camera',
    manufacturer: 'DJI',
    type: 'action_camera',
    has_camera: true,
    has_microphone: true,
    threat_level: 'medium',
    name_patterns: ['dji', 'osmo', 'action'],
    manufacturer_prefixes: ['60:60:1F'],
    ble_manufacturer_ids: [],
  },
  {
    id: 'brilliant_monocle',
    name: 'Brilliant Monocle',
    manufacturer: 'Brilliant Labs',
    type: 'smart_glasses',
    has_camera: true,
    has_microphone: true,
    threat_level: 'high',
    name_patterns: ['monocle', 'brilliant'],
    manufacturer_prefixes: [],
    ble_manufacturer_ids: [],
  },
];

/**
 * Match a detected device against known signatures
 * Returns the matching signature or null
 */
export function matchDevice(
  name: string | null,
  address: string,
  manufacturerData: Record<number, string>
): DeviceSignature | null {
  const addressUpper = address.toUpperCase();
  const nameLower = name?.toLowerCase() || '';

  for (const sig of KNOWN_DEVICES) {
    // Check BLE manufacturer ID (most reliable)
    for (const mfrId of Object.keys(manufacturerData)) {
      if (sig.ble_manufacturer_ids.includes(parseInt(mfrId))) {
        return sig;
      }
    }

    // Check MAC address prefix
    for (const prefix of sig.manufacturer_prefixes) {
      if (addressUpper.startsWith(prefix.toUpperCase())) {
        return sig;
      }
    }

    // Check device name patterns
    if (nameLower) {
      for (const pattern of sig.name_patterns) {
        if (nameLower.includes(pattern)) {
          return sig;
        }
      }
    }
  }

  return null;
}

/**
 * Get threat level color
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
