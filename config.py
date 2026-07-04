"""
IRONYX Process Guard — Configuration Manager
=============================================

Loads and validates the YAML configuration file that controls every aspect
of the EDR: monitoring paths, risk thresholds, whitelists, notification
preferences, database location, and logging.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ── Project root ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"

# ── Default configuration written when no YAML exists ───────────────────────
DEFAULT_CONFIG: dict[str, Any] = {
    "general": {
        "app_name": "IRONYX Process Guard",
        "version": "1.0.0",
        "check_interval": 5,            # seconds between full process scans
        "rapid_respawn_window": 10,     # seconds — N spawns within window = alert
        "rapid_respawn_threshold": 5,
    },
    "database": {
        "path": str(PROJECT_ROOT / "database" / "monitor.db"),
    },
    "monitoring": {
        "filesystem_paths": [
            "/tmp", "/var/tmp", "/dev/shm",
        ],
        "home_watch_dirs": [".cache", ".config", ".local"],
        "input_devices": "/dev/input",
        "watch_network": True,
        "watch_services": True,
        "watch_startup": True,
    },
    "risk": {
        "thresholds": {"low": 30, "medium": 60, "high": 100},
        "scores": {
            "executable_in_tmp": 40,
            "keyboard_device_access": 35,
            "network_beacon": 20,
            "unknown_hash": 20,
            "hidden_file": 15,
            "unsigned_binary": 10,
            "runs_as_root_unexpected": 25,
            "persistence_attempt": 30,
            "cron_modification": 20,
            "systemd_service_creation": 20,
            "zombie_process": 10,
            "rapid_respawn": 25,
            "high_cpu_anomaly": 15,
            "memory_anomaly": 15,
            "orphan_process": 10,
        },
    },
    "rules": {
        "suspicious_processes": str(PROJECT_ROOT / "rules" / "suspicious_processes.json"),
        "suspicious_paths": str(PROJECT_ROOT / "rules" / "suspicious_paths.json"),
        "whitelist": str(PROJECT_ROOT / "rules" / "whitelist.json"),
        "yara_rules_dir": str(PROJECT_ROOT / "rules" / "yara"),
    },
    "notifications": {
        "desktop": True,
        "terminal": True,
        "sound": False,
    },
    "logging": {
        "level": "INFO",
        "app_log": str(PROJECT_ROOT / "logs" / "app.log"),
        "security_log": str(PROJECT_ROOT / "logs" / "security.log"),
        "alert_log": str(PROJECT_ROOT / "logs" / "alert.log"),
        "max_bytes": 5_242_880,   # 5 MB
        "backup_count": 5,
    },
    "api": {
        "host": "127.0.0.1",
        "port": 5555,
        "debug": False,
    },
    "gui": {
        "theme": "dark",
        "refresh_interval": 3,
        "chart_history_points": 60,
    },
    "reports": {
        "output_dir": str(PROJECT_ROOT / "reports"),
        "formats": ["json", "csv", "html", "pdf"],
    },
}


@dataclass
class Config:
    """Runtime configuration object populated from YAML."""

    raw: dict[str, Any] = field(default_factory=dict)

    # ── convenience accessors ───────────────────────────────────────────────
    def get(self, *keys: str, default: Any = None) -> Any:
        """Nested dict access via dotted path."""
        node: Any = self.raw
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

    @property
    def db_path(self) -> str:
        return self.get("database", "path", default=DEFAULT_CONFIG["database"]["path"])

    @property
    def check_interval(self) -> int:
        return int(self.get("general", "check_interval", default=5))

    @property
    def risk_scores(self) -> dict[str, int]:
        return self.get("risk", "scores", default=DEFAULT_CONFIG["risk"]["scores"])

    @property
    def risk_thresholds(self) -> dict[str, int]:
        return self.get("risk", "thresholds", default=DEFAULT_CONFIG["risk"]["thresholds"])

    @property
    def fs_paths(self) -> list[str]:
        return self.get("monitoring", "filesystem_paths", default=[])

    @property
    def home_watch_dirs(self) -> list[str]:
        return self.get("monitoring", "home_watch_dirs", default=[])

    @property
    def whitelist_path(self) -> str:
        return self.get("rules", "whitelist", default="")

    @property
    def suspicious_processes_path(self) -> str:
        return self.get("rules", "suspicious_processes", default="")

    @property
    def suspicious_paths_path(self) -> str:
        return self.get("rules", "suspicious_paths", default="")

    @property
    def app_log_path(self) -> str:
        return self.get("logging", "app_log", default="")

    @property
    def security_log_path(self) -> str:
        return self.get("logging", "security_log", default="")

    @property
    def alert_log_path(self) -> str:
        return self.get("logging", "alert_log", default="")

    @property
    def api_host(self) -> str:
        return self.get("api", "host", default="127.0.0.1")

    @property
    def api_port(self) -> int:
        return int(self.get("api", "port", default=5555))

    @property
    def report_dir(self) -> str:
        return self.get("reports", "output_dir", default=str(PROJECT_ROOT / "reports"))


# ── Loader ──────────────────────────────────────────────────────────────────
def load_config(path: str | Path | None = None) -> Config:
    """Load YAML config, falling back to defaults when missing.

    Parameters
    ----------
    path:
        Optional path to a YAML file.  When *None* the default
        ``config.yaml`` next to this module is used.

    Returns
    -------
    Config
        Populated configuration dataclass.
    """
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    data = DEFAULT_CONFIG.copy()

    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
        # shallow-merge top-level sections
        for key, val in user_cfg.items():
            if isinstance(val, dict) and isinstance(data.get(key), dict):
                data[key].update(val)
            else:
                data[key] = val

    return Config(raw=data)


def write_default_config(path: str | Path | None = None) -> Path:
    """Write the default configuration to *path* (for first-run setup)."""
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as fh:
        yaml.dump(DEFAULT_CONFIG, fh, default_flow_style=False, sort_keys=True)
    return cfg_path
