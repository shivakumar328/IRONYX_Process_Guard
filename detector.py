"""
IRONYX Process Guard — Behavioural Detector
=============================================

Correlates data from all monitors, applies detection rules, and
produces alerts when suspicious behaviour is identified.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config import Config, load_config, PROJECT_ROOT
from database import Database
from logger import get_app_logger, get_security_logger, get_alert_logger
from notifier import Notifier
from risk_engine import RiskEngine, ProcessInfo, RiskResult

log = get_app_logger()
sec_log = get_security_logger()
alert_log = get_alert_logger()


class Detector:
    """Correlate monitor outputs and generate risk-scored alerts."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or load_config()
        self.db = Database(self.cfg)
        self.risk_engine = RiskEngine(self.cfg)
        self.notifier = Notifier(self.cfg)
        self.whitelist: set[str] = self._load_whitelist()
        self.suspicious_names: set[str] = self._load_suspicious_processes()
        self.suspicious_paths: set[str] = self._load_suspicious_paths()

    # ── rule loaders ────────────────────────────────────────────────────────
    def _load_json(self, path: str, key: str) -> set[str]:
        """Load a JSON list from *path* and return it as a set."""
        p = Path(path)
        if not p.exists():
            return set()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return set(data.get(key, []))
        except (json.JSONDecodeError, OSError) as exc:
            log.error("Failed to load %s: %s", path, exc)
            return set()

    def _load_whitelist(self) -> set[str]:
        return self._load_json(self.cfg.whitelist_path, "whitelist")

    def _load_suspicious_processes(self) -> set[str]:
        return self._load_json(self.cfg.suspicious_processes_path, "processes")

    def _load_suspicious_paths(self) -> set[str]:
        return self._load_json(self.cfg.suspicious_paths_path, "paths")

    # ── main detection loop ─────────────────────────────────────────────────
    def evaluate_processes(
        self, processes: list[ProcessInfo]
    ) -> list[dict[str, Any]]:
        """Score every process, persist to DB, and return high-risk alerts."""
        alerts: list[dict[str, Any]] = []
        now = datetime.now().astimezone().isoformat()

        for proc in processes:
            # Skip whitelisted
            if proc.name in self.whitelist:
                continue

            # Check if hash is known
            hash_known = True
            if proc.exe_hash:
                hash_known = self.db.is_hash_known(proc.exe_hash)
                self.db.upsert_hash(proc.exe_hash, proc.exe)

            # Check if process name is in suspicious list
            extra_reasons: list[str] = []
            if proc.name in self.suspicious_names:
                extra_reasons.append(f"Process name matches suspicious list: {proc.name}")

            # Evaluate risk
            result: RiskResult = self.risk_engine.evaluate(proc, hash_known=hash_known)
            result.reasons.extend(extra_reasons)
            result.score = min(result.score + (15 if extra_reasons else 0), 100)
            result.level = self._score_to_level(result.score)

            # Persist process event
            event = {
                "timestamp": now,
                "pid": proc.pid,
                "ppid": proc.ppid,
                "name": proc.name,
                "exe": proc.exe,
                "cmdline": proc.cmdline,
                "username": proc.username,
                "cpu_percent": proc.cpu_percent,
                "mem_mb": proc.mem_mb,
                "status": proc.status,
                "create_time": proc.create_time,
                "exe_hash": proc.exe_hash,
                "risk_score": result.score,
                "risk_level": result.level,
                "reason": "; ".join(result.reasons) if result.reasons else "",
                "action": "monitor",
            }
            self.db.insert_process_event(event)
            self.db.insert_risk_history(proc.pid, result.score, result.level)

            # Generate alert for medium+ risk
            if result.level in ("medium", "high"):
                alert = {
                    "timestamp": now,
                    "pid": proc.pid,
                    "process_name": proc.name,
                    "risk_score": result.score,
                    "risk_level": result.level,
                    "reason": "; ".join(result.reasons),
                    "details": json.dumps({
                        "exe": proc.exe,
                        "cmdline": proc.cmdline[:200],
                        "username": proc.username,
                        "hash": proc.exe_hash[:16] if proc.exe_hash else "",
                    }),
                }
                self.db.insert_alert(alert)
                alerts.append(alert)

                # Log and notify
                alert_log.warning(
                    "ALERT [%s] pid=%s name=%s score=%d reasons=%s",
                    result.level.upper(), proc.pid, proc.name,
                    result.score, result.reasons,
                )
                self.notifier.notify(
                    title=f"Suspicious Process: {proc.name}",
                    message=f"PID {proc.pid} — Risk {result.score} ({result.level})\n"
                            f"Reasons: {'; '.join(result.reasons)}",
                    risk_level=result.level,
                    details={
                        "PID": proc.pid,
                        "Executable": proc.exe,
                        "User": proc.username,
                        "Hash": proc.exe_hash[:16] + "…" if proc.exe_hash else "N/A",
                    },
                )

        return alerts

    # ── filesystem event detection ──────────────────────────────────────────
    def evaluate_filesystem_event(self, event: dict[str, Any]) -> None:
        """Evaluate a filesystem event from the watchdog handler."""
        if event.get("is_executable"):
            sec_log.warning(
                "Executable %s in watched directory: %s",
                event["event"], event["path"],
            )
            self.notifier.notify(
                title="Executable in Watched Directory",
                message=f"{event['event'].capitalize()}: {event['path']}",
                risk_level="medium",
                details={"Flags": ", ".join(event.get("flags", []))},
            )

    # ── service / startup detection ─────────────────────────────────────────
    def evaluate_persistence(self, events: list[dict[str, Any]]) -> None:
        """Evaluate systemd / cron / autostart changes for persistence."""
        for evt in events:
            sec_log.warning("Persistence event: %s", evt)
            self.notifier.notify(
                title="Persistence Attempt Detected",
                message=f"{evt['event'].capitalize()} {evt.get('category', 'entry')}: {evt['path']}",
                risk_level="high",
                details=evt,
            )

    # ── integrity alert ─────────────────────────────────────────────────────
    def evaluate_integrity(self, events: list[dict[str, Any]]) -> None:
        """Evaluate integrity-monitor change events."""
        for evt in events:
            alert = {
                "timestamp": datetime.now().astimezone().isoformat(),
                "pid": None,
                "process_name": "integrity_monitor",
                "risk_score": 100,
                "risk_level": "high",
                "reason": f"Critical file modified: {evt['path']}",
                "details": json.dumps(evt),
            }
            self.db.insert_alert(alert)
            self.notifier.notify(
                title="CRITICAL: System Binary Modified",
                message=f"{evt['path']} has been modified!\n"
                        f"Old: {evt['old_hash'][:16]}…\n"
                        f"New: {evt['new_hash'][:16]}…",
                risk_level="high",
                details=evt,
            )

    # ── helpers ─────────────────────────────────────────────────────────────
    def _score_to_level(self, score: int) -> str:
        thresholds = self.cfg.risk_thresholds
        if score <= thresholds.get("low", 30):
            return "low"
        elif score <= thresholds.get("medium", 60):
            return "medium"
        return "high"
