"""
IRONYX Process Guard — Core Service Monitor
=============================================

Monitors systemd services for unexpected creation or modification,
which can indicate persistence attempts by malware.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from logger import get_app_logger, get_security_logger

log = get_app_logger()
sec_log = get_security_logger()

_SYSTEMD_USER_PATHS = [
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path.home() / ".config" / "systemd" / "user",
    Path("/etc/systemd/user"),
]


class ServiceMonitor:
    """Detect new or modified systemd service files."""

    def __init__(self) -> None:
        self._known_services: dict[str, float] = {}  # path → mtime
        self._first_scan = True

    def scan(self) -> list[dict[str, Any]]:
        """Scan systemd directories and return new/modified service entries."""
        events: list[dict[str, Any]] = []

        for base in _SYSTEMD_USER_PATHS:
            if not base.exists():
                continue
            for svc_file in base.rglob("*.service"):
                try:
                    mtime = svc_file.stat().st_mtime
                except OSError:
                    continue

                key = str(svc_file)
                prev_mtime = self._known_services.get(key)

                if prev_mtime is None:
                    if not self._first_scan:
                        events.append({
                            "event": "created",
                            "path": key,
                            "service": svc_file.stem,
                        })
                        sec_log.warning("New systemd service detected: %s", key)
                elif mtime != prev_mtime:
                    events.append({
                        "event": "modified",
                        "path": key,
                        "service": svc_file.stem,
                    })
                    sec_log.warning("Modified systemd service: %s", key)

                self._known_services[key] = mtime

        self._first_scan = False
        return events

    def list_services(self) -> list[dict[str, Any]]:
        """Return all currently loaded systemd services via ``systemctl``."""
        services: list[dict[str, Any]] = []
        try:
            out = subprocess.run(
                ["systemctl", "list-units", "--type=service",
                 "--all", "--no-pager", "--no-legend", "--plain"],
                capture_output=True, text=True, timeout=15,
            )
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    services.append({
                        "unit": parts[0],
                        "load": parts[1],
                        "active": parts[2],
                        "sub": parts[3],
                        "description": " ".join(parts[4:]),
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            log.debug("systemctl not available")
        return services
