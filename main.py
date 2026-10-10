"""
OPNsense to UniFi Cloud Gateway Max Migrator - Main Launcher.
Launches the Web Dashboard locally and opens the default web browser.
"""

import sys
import os
import argparse
import webbrowser
import threading
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import uvicorn
from src.gui.app import app


def open_browser_delayed(url: str, delay: float = 1.0):
    time.sleep(delay)
    print(f"[*] Opening browser: {url}")
    webbrowser.open(url)


def main():
    parser = argparse.ArgumentParser(
        description="OPNsense 26.x to UniFi Cloud Gateway Max Migrator"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print("=" * 70)
    print("  OPNsense 26.7.5 -> UniFi Cloud Gateway Max Migration Suite")
    print(f"  Web Dashboard running at: {url}")
    print("=" * 70)

    if not args.no_browser:
        threading.Thread(target=open_browser_delayed, args=(url,), daemon=True).start()

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
