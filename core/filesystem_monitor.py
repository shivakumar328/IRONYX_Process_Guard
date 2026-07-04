"""
IRONYX Process Guard — Core Filesystem Monitor
===============================================

Uses *watchdog* to watch /tmp, /dev/shm, /var/tmp, and user home
directories for new, modified, or deleted executable files.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from logger import get_app_logger, get_security_logger

log = get_app_logger()
sec_log = get_security_logger()


def _is_executable(path: str) -> bool:
    """Return *True* if *path* is an executable regular file."""
    try:
        st = os.stat(path)
        return stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111)
    except OSError:
        return False


def _is_hidden(path: str) -> bool:
    """Return *True* if the basename starts with a dot."""
    return os.path.basename(path).startswith(".")


class ExecutableEventHandler(FileSystemEventHandler):
    """Watchdog handler that flags executable file events."""

    def __init__(self, callback: Any = None) -> None:
        self.callback = callback

    def _process_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = event.src_path
        is_exec = _is_executable(path)
        is_hid = _is_hidden(path)

        if not is_exec and not is_hid:
            return

        action = "modified"
        if event.event_type == "created":
            action = "created"
        elif event.event_type == "deleted":
            action = "deleted"
        elif event.event_type == "moved":
            action = "moved"
            path = event.dest_path  # type: ignore[attr-defined]

        flags: list[str] = []
        if is_exec:
            flags.append("executable")
        if is_hid:
            flags.append("hidden")

        sec_log.warning(
            "Filesystem event: %s %s [%s]",
            action, path, ", ".join(flags),
        )

        if self.callback:
            self.callback({
                "event": action,
                "path": path,
                "flags": flags,
                "is_executable": is_exec,
                "is_hidden": is_hid,
            })

    def on_created(self, event: FileSystemEvent) -> None:
        self._process_event(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._process_event(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._process_event(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._process_event(event)


class FilesystemMonitor:
    """Manages watchdog observers for configured paths."""

    def __init__(self, paths: list[str], callback: Any = None) -> None:
        self.paths = paths
        self.callback = callback
        self.observers: list[Observer] = []

    def start(self) -> None:
        """Start watching all configured paths."""
        handler = ExecutableEventHandler(callback=self.callback)
        for p in self.paths:
            if not Path(p).exists():
                log.debug("Skipping non-existent path: %s", p)
                continue
            obs = Observer()
            obs.schedule(handler, p, recursive=True)
            obs.daemon = True
            obs.start()
            self.observers.append(obs)
            log.info("Filesystem monitor started for %s", p)

    def stop(self) -> None:
        """Stop all observers."""
        for obs in self.observers:
            obs.stop()
            obs.join(timeout=5)
        self.observers.clear()
        log.info("Filesystem monitors stopped")
