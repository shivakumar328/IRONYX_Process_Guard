"""
IRONYX Process Guard — Core Integrity Monitor
==============================================

Monitors critical system binaries and configuration files for
unauthorised modifications.  Uses SHA-256 hashing to detect changes.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hashing import compute_sha256
from logger import get_app_logger, get_security_logger

log = get_app_logger()
sec_log = get_security_logger()

# ── Default critical paths to monitor ───────────────────────────────────────
CRITICAL_PATHS: list[str] = [
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/login",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/bin/bash",
    "/usr/bin/zsh",
    "/usr/bin/fish",
    "/usr/lib/systemd/systemd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/system-auth",
]


class IntegrityMonitor:
    """Track SHA-256 hashes of critical files and detect changes."""

    def __init__(self, paths: list[str] | None = None) -> None:
        self.paths = paths or CRITICAL_PATHS
        self._baseline: dict[str, str] = {}  # path → sha256
        self._first_scan = True

    def scan(self) -> list[dict[str, Any]]:
        """Re-hash all monitored files and return change events."""
        events: list[dict[str, Any]] = []

        for p in self.paths:
            path = Path(p)
            if not path.exists():
                continue
            current_hash = compute_sha256(p)
            if current_hash is None:
                continue

            prev_hash = self._baseline.get(p)

            if prev_hash is None:
                # First sighting — just record
                self._baseline[p] = current_hash
            elif current_hash != prev_hash:
                events.append({
                    "event": "modified",
                    "path": p,
                    "old_hash": prev_hash,
                    "new_hash": current_hash,
                })
                sec_log.critical(
                    "INTEGRITY ALERT: %s modified! old=%s new=%s",
                    p, prev_hash[:16], current_hash[:16],
                )
                self._baseline[p] = current_hash

        self._first_scan = False
        return events

    def get_baseline(self) -> dict[str, str]:
        """Return the current hash baseline."""
        return dict(self._baseline)

    def rebuild_baseline(self) -> None:
        """Force a full re-baseline on next scan."""
        self._baseline.clear()
        self._first_scan = True
