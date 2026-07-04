"""
IRONYX Process Guard — Core Network Monitor
=============================================

Collects per-process network connections and flags suspicious
outbound traffic, unexpected listening ports, and communication
with blacklisted IPs.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

from typing import Any

import psutil

from logger import get_app_logger, get_security_logger

log = get_app_logger()
sec_log = get_security_logger()

# ── Suspicious / unexpected ports ────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444,   # Metasploit default
    1337,   # Common C2
    31337,  # Back Orifice
    6667,   # IRC (often used by bots)
    12345,  # NetBus
    27374,  # SubSeven
}

# ── Placeholder blacklist (in production, load from a threat feed) ──────────
BLACKLISTED_IPS: set[str] = set()


class NetworkMonitor:
    """Snapshot network state and detect anomalies."""

    def __init__(self, blacklisted_ips: set[str] | None = None) -> None:
        self.blacklisted_ips = blacklisted_ips or BLACKLISTED_IPS

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a list of per-process network connection records."""
        records: list[dict[str, Any]] = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                pid = p.info["pid"]  # type: ignore[attr-defined]
                name = p.info.get("name", "")  # type: ignore[attr-defined]
                for c in p.connections(kind="inet"):
                    rec: dict[str, Any] = {
                        "pid": pid,
                        "process_name": name,
                        "local_ip": c.laddr.ip if c.laddr else "",
                        "local_port": c.laddr.port if c.laddr else 0,
                        "remote_ip": c.raddr.ip if c.raddr else "",
                        "remote_port": c.raddr.port if c.raddr else 0,
                        "status": c.status,
                        "type": "tcp" if c.type == 1 else "udp",
                        "flags": [],
                    }
                    # Suspicious port
                    if rec["remote_port"] in SUSPICIOUS_PORTS:
                        rec["flags"].append("suspicious_port")
                    if rec["local_port"] in SUSPICIOUS_PORTS:
                        rec["flags"].append("suspicious_listening_port")
                    # Blacklisted IP
                    if rec["remote_ip"] in self.blacklisted_ips:
                        rec["flags"].append("blacklisted_ip")
                    # Unexpected outbound (non-standard port to external)
                    if rec["remote_ip"] and rec["status"] == "ESTABLISHED":
                        if rec["remote_port"] not in (80, 443, 53, 22, 25, 587, 993, 995):
                            rec["flags"].append("unexpected_outbound")

                    if rec["flags"]:
                        sec_log.warning(
                            "Network anomaly: pid=%s name=%s remote=%s:%s flags=%s",
                            pid, name, rec["remote_ip"], rec["remote_port"], rec["flags"],
                        )

                    records.append(rec)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return records

    def get_listening_ports(self) -> list[dict[str, Any]]:
        """Return all listening TCP/UDP ports."""
        listening: list[dict[str, Any]] = []
        for rec in self.snapshot():
            if rec["status"] == "LISTEN":
                listening.append(rec)
        return listening
