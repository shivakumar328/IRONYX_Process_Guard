"""
IRONYX Process Guard — Central Monitor Orchestrator
=====================================================

Coordinates all monitoring subsystems (process, filesystem, network,
input devices, services, startup, integrity) in a single polling loop.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from config import Config, load_config
from core import (
    ProcessMonitor,
    FilesystemMonitor,
    NetworkMonitor,
    InputDeviceMonitor,
    ServiceMonitor,
    StartupMonitor,
    IntegrityMonitor,
)
from detector import Detector
from logger import get_app_logger, get_security_logger
from scanner import Scanner

log = get_app_logger()
sec_log = get_security_logger()


class Monitor:
    """Top-level orchestrator that runs all monitors in a background thread."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or load_config()
        self.process_monitor = ProcessMonitor()
        self.fs_monitor = FilesystemMonitor(
            paths=self._build_fs_paths(),
            callback=self._on_fs_event,
        )
        self.network_monitor = NetworkMonitor()
        self.input_monitor = InputDeviceMonitor()
        self.service_monitor = ServiceMonitor()
        self.startup_monitor = StartupMonitor()
        self.integrity_monitor = IntegrityMonitor()
        self.detector = Detector(self.cfg)
        self.scanner = Scanner(self.cfg)

        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._latest_processes: list = []
        self._latest_alerts: list[dict[str, Any]] = []
        self._latest_network: list[dict[str, Any]] = []
        self._latest_keyboard: list[dict[str, Any]] = []

    def _build_fs_paths(self) -> list[str]:
        """Build the full list of filesystem paths to watch."""
        paths = list(self.cfg.fs_paths)
        home = str(__import__("pathlib").Path.home())
        for d in self.cfg.home_watch_dirs:
            paths.append(f"{home}/{d}")
        return paths

    # ── lifecycle ───────────────────────────────────────────────────────────
    def start(self) -> None:
        """Start all monitors in a background thread."""
        if self._running:
            return
        self._running = True
        self.fs_monitor.start()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ironyx-monitor")
        self._thread.start()
        log.info("IRONYX Process Guard monitor started")

    def stop(self) -> None:
        """Stop all monitors."""
        self._running = False
        self.fs_monitor.stop()
        if self._thread:
            self._thread.join(timeout=10)
        log.info("IRONYX Process Guard monitor stopped")

    # ── main loop ───────────────────────────────────────────────────────────
    def _loop(self) -> None:
        """Main monitoring loop — runs until :meth:`stop` is called."""
        interval = self.cfg.check_interval

        while self._running:
            try:
                # 1. Process snapshot + risk evaluation
                procs = self.process_monitor.snapshot()
                with self._lock:
                    self._latest_processes = procs
                alerts = self.detector.evaluate_processes(procs)
                if alerts:
                    with self._lock:
                        self._latest_alerts = alerts

                # 2. Network snapshot
                net = self.network_monitor.snapshot()
                with self._lock:
                    self._latest_network = net

                # 3. Keyboard device access
                kb = self.input_monitor.get_keyboard_processes()
                with self._lock:
                    self._latest_keyboard = kb

                # 4. Service / startup / integrity (less frequent)
                svc_events = self.service_monitor.scan()
                if svc_events:
                    self.detector.evaluate_persistence(svc_events)

                startup_events = self.startup_monitor.scan()
                if startup_events:
                    self.detector.evaluate_persistence(startup_events)

                integrity_events = self.integrity_monitor.scan()
                if integrity_events:
                    self.detector.evaluate_integrity(integrity_events)

            except Exception as exc:
                log.error("Monitor loop error: %s", exc, exc_info=True)

            time.sleep(interval)

    # ── callbacks ───────────────────────────────────────────────────────────
    def _on_fs_event(self, event: dict[str, Any]) -> None:
        """Callback for filesystem monitor events."""
        self.detector.evaluate_filesystem_event(event)

    # ── data accessors (thread-safe) ─────────────────────────────────────────
    def get_processes(self) -> list:
        with self._lock:
            return list(self._latest_processes)

    def get_alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._latest_alerts)

    def get_network(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._latest_network)

    def get_keyboard_access(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._latest_keyboard)

    def get_stats(self) -> dict[str, Any]:
        return self.detector.db.get_stats()
