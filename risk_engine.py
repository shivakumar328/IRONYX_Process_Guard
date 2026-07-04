"""
IRONYX Process Guard — Risk Scoring Engine
===========================================

Evaluates each process against behavioural rules and produces a numeric
risk score (0–100) and a categorical level (low / medium / high).

Scoring is additive — each triggered rule contributes points defined in
the YAML configuration under ``risk.scores``.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from config import Config, load_config

# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class ProcessInfo:
    """Normalised process snapshot consumed by the risk engine."""

    pid: int
    ppid: int
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    cpu_percent: float = 0.0
    mem_mb: float = 0.0
    status: str = ""
    create_time: str = ""
    exe_hash: str = ""
    open_files: list[str] = field(default_factory=list)
    connections: list[dict[str, Any]] = field(default_factory=list)
    is_root: bool = False
    is_zombie: bool = False
    is_orphan: bool = False
    accesses_keyboard: bool = False
    is_hidden: bool = False
    respawn_count: int = 0


@dataclass
class RiskResult:
    """Output of a single risk evaluation."""

    score: int = 0
    level: str = "low"
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


# ── Suspicious path prefixes ────────────────────────────────────────────────
_SUSPICIOUS_PREFIXES = ("/tmp", "/dev/shm", "/var/tmp")


# ── Engine ──────────────────────────────────────────────────────────────────

class RiskEngine:
    """Stateless risk evaluator driven by configurable score weights."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or load_config()
        self.scores: dict[str, int] = self.cfg.risk_scores
        self.thresholds: dict[str, int] = self.cfg.risk_thresholds

    # ── main entry ──────────────────────────────────────────────────────────
    def evaluate(self, proc: ProcessInfo, hash_known: bool = True) -> RiskResult:
        """Evaluate *proc* and return a :class:`RiskResult`.

        Parameters
        ----------
        proc:
            Normalised process info.
        hash_known:
            Whether the executable's SHA-256 has been seen before.

        Returns
        -------
        RiskResult
            Score, level, and human-readable reasons.
        """
        result = RiskResult()
        s = self.scores

        # 1. Executable in suspicious location
        if proc.exe and any(proc.exe.startswith(p) for p in _SUSPICIOUS_PREFIXES):
            self._add(result, s["executable_in_tmp"], f"Executable running from suspicious path: {proc.exe}")

        # 2. Keyboard device access
        if proc.accesses_keyboard:
            self._add(result, s["keyboard_device_access"], "Process has keyboard input device handle open")

        # 3. Network beaconing (many short connections to same remote IP)
        beacon_ips = self._detect_beacon(proc.connections)
        if beacon_ips:
            self._add(result, s["network_beacon"], f"Possible network beaconing to: {', '.join(beacon_ips)}")

        # 4. Unknown executable hash
        if proc.exe and not hash_known:
            self._add(result, s["unknown_hash"], "Executable hash not in known-good database")

        # 5. Hidden file
        if proc.is_hidden:
            self._add(result, s["hidden_file"], "Process executable is hidden (dotfile or chattr)")

        # 6. Runs as root unexpectedly
        if proc.is_root and proc.exe and any(proc.exe.startswith(p) for p in _SUSPICIOUS_PREFIXES):
            self._add(result, s["runs_as_root_unexpected"], "Root process running from suspicious path")

        # 7. Zombie process
        if proc.is_zombie:
            self._add(result, s["zombie_process"], "Zombie process detected")

        # 8. Orphan process (parent PID 1 and not a daemon)
        if proc.is_orphan:
            self._add(result, s["orphan_process"], f"Orphan process (PPID=1): {proc.name}")

        # 9. Rapid respawn
        if proc.respawn_count >= 5:
            self._add(result, s["rapid_respawn"], f"Rapid respawn: {proc.respawn_count} times in window")

        # 10. High CPU anomaly (> 90 %)
        if proc.cpu_percent > 90:
            self._add(result, s["high_cpu_anomaly"], f"High CPU usage: {proc.cpu_percent:.1f}%")

        # 11. Memory anomaly (> 2 GB)
        if proc.mem_mb > 2048:
            self._add(result, s["memory_anomaly"], f"High memory usage: {proc.mem_mb:.0f} MB")

        # Clamp to 100
        result.score = min(result.score, 100)
        result.level = self._score_to_level(result.score)
        return result

    # ── helpers ─────────────────────────────────────────────────────────────
    @staticmethod
    def _add(result: RiskResult, points: int, reason: str) -> None:
        result.score += points
        result.reasons.append(reason)

    def _score_to_level(self, score: int) -> str:
        if score <= self.thresholds.get("low", 30):
            return "low"
        elif score <= self.thresholds.get("medium", 60):
            return "medium"
        return "high"

    @staticmethod
    def _detect_beacon(connections: list[dict[str, Any]], min_count: int = 5) -> list[str]:
        """Return remote IPs that appear in >= *min_count* connections."""
        ip_counts: dict[str, int] = {}
        for c in connections:
            ip = c.get("remote_ip", "")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        return [ip for ip, cnt in ip_counts.items() if cnt >= min_count]
