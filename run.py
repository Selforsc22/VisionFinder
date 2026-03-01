#!/usr/bin/env python3
"""
Bluetooth Recording Device Scanner
Main entry point for the application
"""

import argparse
import sys
import logging

def main():
    parser = argparse.ArgumentParser(
        description='Bluetooth Recording Device Scanner - Detect nearby recording devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                    # Start web UI on default port (5000)
  python run.py --port 8080        # Start web UI on port 8080
  python run.py --cli              # Run command-line scanner only
  python run.py --cli --timeout 30 # Scan for 30 seconds in CLI mode
        """
    )

    parser.add_argument('--port', type=int, default=5000,
                        help='Port for web server (default: 5000)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--cli', action='store_true',
                        help='Run in CLI mode (no web interface)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Scan timeout in seconds for CLI mode (default: 10)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--continuous', action='store_true',
                        help='Run continuous scanning in CLI mode')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    if args.cli:
        # CLI mode
        import asyncio
        from src.scanner import BluetoothScanner, DetectedDevice

        scanner = BluetoothScanner()

        def on_threat(device: DetectedDevice):
            print(f"\n{'='*60}")
            print(f"  ALERT: RECORDING DEVICE DETECTED!")
            print(f"  Device: {device.matched_signature.name if device.matched_signature else 'Unknown'}")
            print(f"  Address: {device.address}")
            print(f"  Signal: {device.rssi} dBm")
            if device.matched_signature:
                print(f"  Has Camera: {'Yes' if device.matched_signature.has_camera else 'No'}")
                print(f"  Has Microphone: {'Yes' if device.matched_signature.has_microphone else 'No'}")
            print(f"{'='*60}\n")

        scanner.on_threat_detected = on_threat

        if args.continuous:
            print("Starting continuous scan... Press Ctrl+C to stop.")
            try:
                asyncio.run(scanner.start_continuous_scan())
            except KeyboardInterrupt:
                print("\nScan stopped.")
                scanner.stop_scanning()
        else:
            print(f"Scanning for {args.timeout} seconds...")
            devices = asyncio.run(scanner.scan_once(timeout=args.timeout))

            print(f"\nFound {len(devices)} devices:")
            print("-" * 60)

            for device in sorted(devices, key=lambda d: d.rssi, reverse=True):
                threat_marker = " [!!! THREAT !!!]" if device.is_potential_threat else ""
                print(f"  {device.name or 'Unknown':<30} {device.address}  {device.rssi:>4} dBm{threat_marker}")
                if device.is_potential_threat and device.matched_signature:
                    print(f"      -> Identified as: {device.matched_signature.name}")

            threats = scanner.get_threats()
            if threats:
                print(f"\n{'='*60}")
                print(f"  WARNING: {len(threats)} potential recording device(s) detected!")
                print(f"{'='*60}")
            else:
                print("\n  No recording devices detected.")

    else:
        # Web UI mode
        try:
            from src.web_app import run_server
            logger.info(f"Starting Bluetooth Scanner Web UI on http://{args.host}:{args.port}")
            print(f"\n{'='*60}")
            print(f"  Bluetooth Recording Device Scanner")
            print(f"  Web UI available at: http://localhost:{args.port}")
            print(f"{'='*60}\n")
            run_server(host=args.host, port=args.port, debug=args.debug)
        except ImportError as e:
            logger.error(f"Failed to import web app: {e}")
            logger.error("Make sure all dependencies are installed: pip install -r requirements.txt")
            sys.exit(1)


if __name__ == '__main__':
    main()
