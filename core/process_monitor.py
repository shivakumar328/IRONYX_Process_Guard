"""
IRONYX Process Guard — Core Process Monitor
=============================================

Enumerates running processes via *psutil*, enriches each with hash,
network connections, open files, and keyboard-device access flags.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import psutil

from hashing import get_cached_hash
from logger import get_app_logger, get_security_logger
from risk_engine import ProcessInfo

log = get_app_logger()
sec_log = get_security_logger()

# ── Keyboard device paths ───────────────────────────────────────────────────
_INPUT_DEV_PREFIX = "/dev/input/event"


def _is_keyboard_fd(fd_path: str) -> bool:
    """Heuristic: /dev/input/eventN that is not a mouse."""
    return fd_path.startswith(_INPUT_DEV_PREFIX)


class ProcessMonitor:
    """Snapshot all running processes and return :class:`ProcessInfo` objects."""

    def __init__(self) -> None:
        self._prev_pids: set[int] = set()
        self._respawn_tracker: dict[str, list[float]] = {}

    # ── public API ──────────────────────────────────────────────────────────
    def snapshot(self) -> list[ProcessInfo]:
        """Return a list of :class:`ProcessInfo` for every running process."""
        procs: list[ProcessInfo] = []
        current_pids: set[int] = set()

        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline",
                                       "username", "cpu_percent", "memory_info",
                                       "status", "create_time"]):
            try:
                info = p.info  # type: ignore[attr-defined]
                pid = info["pid"]
                current_pids.add(pid)

                pi = ProcessInfo(
                    pid=pid,
                    ppid=info.get("ppid", 0),
                    name=info.get("name", ""),
                    exe=info.get("exe") or "",
                    cmdline=" ".join(info.get("cmdline") or []),
                    username=info.get("username") or "",
                    cpu_percent=info.get("cpu_percent", 0.0) or 0.0,
                    mem_mb=(info.get("memory_info").rss / 1_048_576) if info.get("memory_info") else 0.0,
                    status=info.get("status", ""),
                    create_time=datetime.fromtimestamp(
                        info.get("create_time", 0)
                    ).isoformat() if info.get("create_time") else "",
                    is_root=(info.get("username") in ("root", "0")),
                    is_zombie=(info.get("status") == psutil.STATUS_ZOMBIE),
                    is_orphan=(info.get("ppid") == 1 and info.get("name", "") not in
                               _DAEMON_NAMES),
                )

                # Hash
                if pi.exe:
                    pi.exe_hash = get_cached_hash(pi.exe) or ""

                # Open files — check for keyboard device access
                try:
                    for f in p.open_files():
                        pi.open_files.append(f.path)
                        if _is_keyboard_fd(f.path):
                            pi.accesses_keyboard = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # Network connections
                try:
                    for c in p.connections(kind="inet"):
                        pi.connections.append({
                            "local_ip": c.laddr.ip if c.laddr else "",
                            "local_port": c.laddr.port if c.laddr else 0,
                            "remote_ip": c.raddr.ip if c.raddr else "",
                            "remote_port": c.raddr.port if c.raddr else 0,
                            "status": c.status,
                            "type": "tcp" if c.type == 1 else "udp",
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # Hidden executable
                if pi.exe and os.path.basename(pi.exe).startswith("."):
                    pi.is_hidden = True

                # Respawn tracking
                if pi.name:
                    now = time.time()
                    times = self._respawn_tracker.get(pi.name, [])
                    times = [t for t in times if now - t < 10]
                    times.append(now)
                    self._respawn_tracker[pi.name] = times
                    pi.respawn_count = len(times)

                procs.append(pi)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Detect new / terminated
        new_pids = current_pids - self._prev_pids
        gone_pids = self._prev_pids - current_pids
        if new_pids:
            sec_log.info("New processes: %s", new_pids)
        if gone_pids:
            sec_log.info("Terminated processes: %s", gone_pids)
        self._prev_pids = current_pids

        return procs

    def get_process_tree(self, pid: int) -> dict[str, Any]:
        """Return a process tree rooted at *pid*."""
        tree: dict[str, Any] = {}
        try:
            p = psutil.Process(pid)
            tree["pid"] = pid
            tree["name"] = p.name()
            tree["exe"] = p.exe()
            tree["cmdline"] = p.cmdline()
            tree["children"] = []
            for child in p.children(recursive=True):
                tree["children"].append({
                    "pid": child.pid,
                    "name": child.name(),
                    "exe": child.exe(),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return tree


# ── Common daemon names that legitimately have PPID 1 ───────────────────────
_DAEMON_NAMES = {
    "systemd", "systemd-journald", "systemd-udevd", "systemd-logind",
    "systemd-resolved", "systemd-networkd", "dbus-daemon", "cron",
    "agetty", "sshd", "rsyslogd", "NetworkManager", "wpa_supplicant",
    "auditd", "bluetoothd", "colord", "polkitd", "rtkit-daemon",
    "avahi-daemon", "cupsd", "gdm", "sddm", "lightdm", "xdm",
    "init", "kthreadd",
}
