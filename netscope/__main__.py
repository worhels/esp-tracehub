"""NETSCOPE entry point — ``python -m netscope``."""

from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NETSCOPE — Real-time network monitoring TUI",
    )
    parser.add_argument(
        "--port",
        default="COM3",
        help="Serial port for ESP32 (default: COM3)",
    )
    parser.add_argument(
        "--no-tshark",
        action="store_true",
        help="Disable TShark packet capture",
    )
    parser.add_argument(
        "--no-esp",
        action="store_true",
        help="Disable ESP32 serial connection",
    )
    parser.add_argument(
        "--export-dir",
        default=".",
        help="Directory for exported capture files (default: current dir)",
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="TShark capture interface (e.g. 'Wi-Fi', 'Ethernet')",
    )

    args = parser.parse_args()

    from .netview import NetScopeApp

    app = NetScopeApp(
        esp_port=args.port,
        no_tshark=args.no_tshark,
        no_esp=args.no_esp,
        export_dir=args.export_dir,
        tshark_interface=args.interface,
    )
    app.run()


if __name__ == "__main__":
    main()
