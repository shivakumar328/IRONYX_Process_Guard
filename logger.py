"""
IRONYX Process Guard — Logging Setup
=====================================

Creates three rotating log streams:

* **app.log**      — general application lifecycle
* **security.log** — security-relevant events (process spawns, file changes)
* **alert.log**    — high-risk alerts that triggered notifications

Each stream rotates at 5 MB with 5 backups.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import Config, load_config

# ── Format strings ──────────────────────────────────────────────────────────
_FMT = "%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

_loggers: dict[str, logging.Logger] = {}


def _ensure_dir(path: str) -> None:
    """Create parent directory for *path* if it does not exist."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def _make_logger(
    name: str,
    log_file: str,
    level: int = logging.INFO,
) -> logging.Logger:
    """Build a rotating-file logger."""
    if name in _loggers:
        return _loggers[name]

    _ensure_dir(log_file)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    # Avoid duplicate handlers on re-init
    if not logger.handlers:
        handler = RotatingFileHandler(
            log_file,
            maxBytes=5_242_880,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(_FMT, datefmt=_DATEFMT))
        logger.addHandler(handler)

        # Also echo to console at WARNING+
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        console.setFormatter(logging.Formatter(_FMT, datefmt=_DATEFMT))
        logger.addHandler(console)

    _loggers[name] = logger
    return logger


def get_app_logger(cfg: Config | None = None) -> logging.Logger:
    """Return the general application logger."""
    cfg = cfg or load_config()
    level = getattr(logging, cfg.get("logging", "level", default="INFO").upper(), logging.INFO)
    return _make_logger("ironyx.app", cfg.app_log_path, level)


def get_security_logger(cfg: Config | None = None) -> logging.Logger:
    """Return the security-event logger."""
    cfg = cfg or load_config()
    level = getattr(logging, cfg.get("logging", "level", default="INFO").upper(), logging.INFO)
    return _make_logger("ironyx.security", cfg.security_log_path, level)


def get_alert_logger(cfg: Config | None = None) -> logging.Logger:
    """Return the alert logger (high-risk events only)."""
    cfg = cfg or load_config()
    level = getattr(logging, cfg.get("logging", "level", default="INFO").upper(), logging.INFO)
    return _make_logger("ironyx.alert", cfg.alert_log_path, level)
