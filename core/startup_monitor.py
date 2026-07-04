"""
IRONYX Process Guard — Core Startup Monitor
=============================================

Monitors autostart entries and cron jobs for persistence attempts.

Watched locations:
  * ~/.config/autostart/*.desktop
  * /etc/xdg/autostart/*.desktop
  * /etc/crontab
  * /etc/cron.d/*
  * user crontab (crontab -l)

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

_AUTOSTART_DIRS = [
    Path("/etc/xdg/autostart"),
    Path.home() / ".config" / "autostart",
]

_CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
]


class StartupMonitor:
    """Detect new or modified autostart and cron entries."""

    def __init__(self) -> None:
        self._known: dict[str, float] = {}
        self._first_scan = True

    def scan(self) -> list[dict[str, Any]]:
        """Return new/modified startup and cron entries."""
        events: list[dict[str, Any]] = []

        # Autostart .desktop files
        for d in _AUTOSTART_DIRS:
            if d.exists():
                for f in d.glob("*.desktop"):
                    self._check_file(f, events, category="autostart")

        # Cron files
        for p in _CRON_PATHS:
            if p.is_file():
                self._check_file(p, events, category="cron")
            elif p.is_dir():
                for f in p.iterdir():
                    if f.is_file():
                        self._check_file(f, events, category="cron")

        # User crontab
        user_cron = self._get_user_crontab()
        if user_cron:
            key = "user_crontab"
            prev = self._known.get(key)
            if prev is None and not self._first_scan:
                events.append({
                    "event": "created",
                    "path": key,
                    "category": "cron",
                    "content_preview": user_cron[:200],
                })
                sec_log.warning("New user crontab entries detected")
            self._known[key] = hash(user_cron)  # type: ignore[assignment]

        self._first_scan = False
        return events

    def _check_file(self, path: Path, events: list, category: str) -> None:
        """Check a single file for new/modified status."""
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return
        key = str(path)
        prev = self._known.get(key)
        if prev is None:
            if not self._first_scan:
                events.append({
                    "event": "created",
                    "path": key,
                    "category": category,
                })
                sec_log.warning("New %s entry: %s", category, key)
        elif mtime != prev:
            events.append({
                "event": "modified",
                "path": key,
                "category": category,
            })
            sec_log.warning("Modified %s entry: %s", category, key)
        self._known[key] = mtime

    @staticmethod
    def _get_user_crontab() -> str:
        """Return the current user's crontab content, or empty string."""
        try:
            out = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=10,
            )
            return out.stdout if out.returncode == 0 else ""
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ""

    def list_autostart_entries(self) -> list[dict[str, str]]:
        """Return all autostart .desktop entries."""
        entries: list[dict[str, str]] = []
        for d in _AUTOSTART_DIRS:
            if d.exists():
                for f in d.glob("*.desktop"):
                    name = f.stem
                    exec_cmd = ""
                    try:
                        for line in f.read_text().splitlines():
                            if line.startswith("Exec="):
                                exec_cmd = line[5:]
                                break
                    except OSError:
                        pass
                    entries.append({
                        "name": name,
                        "path": str(f),
                        "exec": exec_cmd,
                    })
        return entries
