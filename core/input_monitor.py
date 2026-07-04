"""
IRONYX Process Guard — Core Input Device Monitor
=================================================

Detects which processes currently have keyboard input device handles
(/dev/input/event*) open.  This is the primary heuristic for detecting
possible keylogger behaviour — **without** capturing any keystrokes.

The module only reads *which* file descriptors are open, never the data
flowing through them.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import psutil

from logger import get_app_logger, get_security_logger

log = get_app_logger()
sec_log = get_security_logger()

_INPUT_PREFIX = "/dev/input/event"


class InputDeviceMonitor:
    """Detect processes with keyboard device handles open."""

    def __init__(self, known_keyboard_processes: set[str] | None = None) -> None:
        # Processes that legitimately read keyboard events (X11, Wayland, libinput)
        self.known: set[str] = known_keyboard_processes or {
            "Xorg", "Xwayland", "gnome-shell", "kwin_x11", "kwin_wayland",
            "sway", "weston", "libinput", "mutter", "gdm", "sddm", "lightdm",
            "systemd", "logind", "evtest", "xev", "libinput-debug-events",
            "irq/","kworker", "gamepad", "ds4drv",
        }

    def get_keyboard_processes(self) -> list[dict[str, Any]]:
        """Return a list of processes that have /dev/input/event* handles open.

        Each entry contains::

            {pid, name, exe, username, devices: [...], is_known: bool}
        """
        results: list[dict[str, Any]] = []
        seen_pids: set[int] = set()

        # Method 1: psutil open_files
        for p in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                pid = p.info["pid"]  # type: ignore[attr-defined]
                if pid in seen_pids:
                    continue
                devices: list[str] = []
                for f in p.open_files():
                    if f.path.startswith(_INPUT_PREFIX):
                        devices.append(f.path)
                if devices:
                    name = p.info.get("name", "")  # type: ignore[attr-defined]
                    results.append({
                        "pid": pid,
                        "name": name,
                        "exe": p.info.get("exe", ""),  # type: ignore[attr-defined]
                        "username": p.info.get("username", ""),  # type: ignore[attr-defined]
                        "devices": devices,
                        "is_known": name in self.known,
                        "source": "psutil",
                    })
                    seen_pids.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Method 2: lsof fallback (catches FDs psutil might miss)
        lsof_pids = self._lsof_keyboard_pids()
        for pid, devices in lsof_pids.items():
            if pid in seen_pids:
                continue
            try:
                p = psutil.Process(pid)
                name = p.name()
                results.append({
                    "pid": pid,
                    "name": name,
                    "exe": p.exe(),
                    "username": p.username(),
                    "devices": devices,
                    "is_known": name in self.known,
                    "source": "lsof",
                })
                seen_pids.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Log unknown processes
        for r in results:
            if not r["is_known"]:
                sec_log.warning(
                    "UNKNOWN process accessing keyboard devices: pid=%s name=%s user=%s devices=%s",
                    r["pid"], r["name"], r["username"], r["devices"],
                )

        return results

    def _lsof_keyboard_pids(self) -> dict[int, list[str]]:
        """Use ``lsof`` as a fallback to find PIDs with /dev/input handles."""
        result: dict[int, list[str]] = {}
        try:
            out = subprocess.run(
                ["lsof", "+c", "0", "/dev/input"],
                capture_output=True, text=True, timeout=10,
            )
            for line in out.stdout.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) >= 10:
                    try:
                        pid = int(parts[1])
                        dev = parts[-1]
                        if dev.startswith(_INPUT_PREFIX):
                            result.setdefault(pid, []).append(dev)
                    except (ValueError, IndexError):
                        continue
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            log.debug("lsof not available or timed out — using psutil only")
        return result

    def list_input_devices(self) -> list[dict[str, str]]:
        """List all /dev/input/event* devices with their names."""
        devices: list[dict[str, str]] = []
        base = Path("/dev/input")
        if not base.exists():
            return devices
        for entry in sorted(base.glob("event*")):
            name_path = Path("/sys/class/input") / entry.name / "device" / "name"
            dev_name = ""
            try:
                dev_name = name_path.read_text().strip()
            except OSError:
                pass
            devices.append({
                "device": str(entry),
                "name": dev_name,
            })
        return devices
