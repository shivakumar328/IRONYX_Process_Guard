#!/usr/bin/env python3
"""
IRONYX Process Guard — Unified Launcher
========================================

Single entry point that starts:
  1. The IRONYX monitoring engine (background thread)
  2. The Flask backend API (real-time system data)
  3. The Crystal Glass web frontend (served by Flask)

Usage:
    python run.py                 # Default: http://127.0.0.1:5555
    python run.py --port 8080     # Custom port
    python run.py --host 0.0.0.0  # Listen on all interfaces
    sudo python run.py            # Root for full process visibility

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import load_config
from monitor import Monitor
from web.app import create_app


def main() -> None:
    """Start the unified IRONYX Process Guard application."""
    parser = argparse.ArgumentParser(
        description="IRONYX Process Guard — Linux EDR with Crystal Glass Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                  # Start on http://127.0.0.1:5555
  sudo python run.py             # Root for full process visibility
  python run.py --port 8080      # Custom port
  python run.py --no-browser     # Don't auto-open browser
  python run.py --host 0.0.0.0   # Listen on all interfaces
""",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5555,
                        help="Port number (default: 5555)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't auto-open the browser")
    parser.add_argument("--debug", action="store_true",
                        help="Enable Flask debug mode")
    args = parser.parse_args()

    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║         IRONYX Process Guard  v1.0.0             ║")
    print("  ║     Linux EDR + Crystal Glass Dashboard          ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    # Load configuration
    cfg = load_config()

    # Start the monitoring engine in background
    print("  [1/3] Starting monitoring engine...")
    monitor = Monitor(cfg)
    monitor.start()
    print("        ✓ Process monitor active")
    print("        ✓ Filesystem monitor active")
    print("        ✓ Network monitor active")
    print("        ✓ Input device monitor active")
    print("        ✓ Integrity monitor active")
    print("        ✓ Service & startup monitor active")
    print()

    # Create Flask app with the monitor
    print("  [2/3] Starting Flask backend API...")
    app = create_app(monitor=monitor, cfg=cfg)

    url = f"http://{args.host}:{args.port}"
    print(f"        ✓ API endpoints ready at {url}/api/*")
    print()

    # Auto-open browser
    if not args.no_browser:
        print("  [3/3] Opening Crystal Glass dashboard in browser...")
        def _open_browser() -> None:
            time.sleep(1.5)
            webbrowser.open(f"http://127.0.0.1:{args.port}")
        threading.Thread(target=_open_browser, daemon=True).start()
    else:
        print("  [3/3] Browser auto-open disabled.")
    print()
    print(f"  ─────────────────────────────────────────────────────")
    print(f"  Dashboard:  {url}")
    print(f"  API:        {url}/api/processes")
    print(f"  ─────────────────────────────────────────────────────")
    print()
    print("  Press Ctrl+C to stop.")
    print()

    # Graceful shutdown
    def _shutdown(signum: int, frame: object) -> None:
        print("\n\n  Shutting down IRONYX Process Guard...")
        monitor.stop()
        print("  ✓ Monitoring engine stopped.")
        print("  Goodbye.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Start Flask (blocking)
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            use_reloader=False,  # Don't reloader — monitor is already running
        )
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
