"""
IRONYX Process Guard — YARA & Hash Scanner
===========================================

Scans executables on disk using YARA rules (when available) and
cross-references SHA-256 hashes against the local database.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from database import Database
from hashing import compute_sha256
from logger import get_app_logger, get_security_logger
from config import Config, load_config

log = get_app_logger()
sec_log = get_security_logger()


class Scanner:
    """Filesystem scanner with optional YARA integration."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or load_config()
        self.db = Database(self.cfg)
        self._yara_rules = None
        self._load_yara()

    def _load_yara(self) -> None:
        """Attempt to compile YARA rules from the rules directory."""
        yara_dir = Path(self.cfg.get("rules", "yara_rules_dir", default=""))
        if not yara_dir.exists():
            log.info("No YARA rules directory found — skipping YARA scanning")
            return
        try:
            import yara  # type: ignore
            rule_files: dict[str, str] = {}
            for yf in yara_dir.glob("*.yar"):
                rule_files[yf.stem] = str(yf)
            if rule_files:
                self._yara_rules = yara.compile(**rule_files)
                log.info("Loaded %d YARA rule files", len(rule_files))
        except ImportError:
            log.info("yara-python not installed — YARA scanning disabled")
        except Exception as exc:
            log.warning("Failed to compile YARA rules: %s", exc)

    def scan_file(self, file_path: str | Path) -> dict[str, Any]:
        """Scan a single file: hash + YARA (if available).

        Returns
        -------
        dict
            {path, sha256, known, yara_matches: [...]}
        """
        p = Path(file_path)
        result: dict[str, Any] = {
            "path": str(p),
            "sha256": None,
            "known": False,
            "yara_matches": [],
        }

        if not p.is_file():
            return result

        sha = compute_sha256(p)
        result["sha256"] = sha
        if sha:
            result["known"] = self.db.is_hash_known(sha)
            self.db.upsert_hash(sha, str(p))

        if self._yara_rules:
            try:
                matches = self._yara_rules.match(str(p))
                result["yara_matches"] = [str(m) for m in matches]
                if matches:
                    sec_log.warning("YARA match in %s: %s", p, matches)
            except Exception as exc:
                log.debug("YARA scan error for %s: %s", p, exc)

        return result

    def scan_directory(
        self, directory: str | Path, recursive: bool = True
    ) -> list[dict[str, Any]]:
        """Scan all executable files in *directory*."""
        results: list[dict[str, Any]] = []
        base = Path(directory)
        if not base.exists():
            return results

        iterator = base.rglob("*") if recursive else base.iterdir()
        for entry in iterator:
            try:
                if not entry.is_file():
                    continue
                st = entry.stat()
                if not (st.st_mode & 0o111):  # not executable
                    continue
                results.append(self.scan_file(entry))
            except (PermissionError, OSError):
                continue

        return results

    def scan_running_executables(self, processes: list) -> list[dict[str, Any]]:
        """Scan the on-disk executables of currently running processes."""
        results: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for proc in processes:
            if proc.exe and proc.exe not in seen_paths:
                seen_paths.add(proc.exe)
                res = self.scan_file(proc.exe)
                res["pid"] = proc.pid
                res["process_name"] = proc.name
                results.append(res)
        return results
