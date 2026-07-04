"""
IRONYX Process Guard — Unit Tests
==================================

Run with: pytest tests/ -v --cov=. --cov-report=term-missing

Author : IRONYX Security
License: MIT
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestHashing(unittest.TestCase):
    """Tests for the hashing module."""

    def test_compute_sha256_valid_file(self) -> None:
        import hashing
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"IRONYX test data")
            f.flush()
            path = f.name
        try:
            digest = hashing.compute_sha256(path)
            self.assertIsNotNone(digest)
            self.assertEqual(len(digest), 64)  # SHA-256 hex = 64 chars
        finally:
            os.unlink(path)

    def test_compute_sha256_nonexistent(self) -> None:
        import hashing
        result = hashing.compute_sha256("/nonexistent/path/file")
        self.assertIsNone(result)

    def test_has_executable_changed(self) -> None:
        import hashing
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"original")
            f.flush()
            path = f.name
        try:
            h1 = hashing.get_cached_hash(path)
            self.assertIsNotNone(h1)
            # Same content → no change
            self.assertFalse(hashing.has_executable_changed(path, h1))
            # Different hash → change detected
            self.assertTrue(hashing.has_executable_changed(path, "0" * 64))
        finally:
            os.unlink(path)


class TestRiskEngine(unittest.TestCase):
    """Tests for the risk scoring engine."""

    def setUp(self) -> None:
        from risk_engine import ProcessInfo, RiskEngine
        self.engine = RiskEngine()
        self.ProcessInfo = ProcessInfo

    def test_low_risk_clean_process(self) -> None:
        proc = self.ProcessInfo(pid=1, ppid=0, name="bash", exe="/usr/bin/bash")
        result = self.engine.evaluate(proc, hash_known=True)
        self.assertEqual(result.level, "low")
        self.assertEqual(result.score, 0)

    def test_executable_in_tmp(self) -> None:
        proc = self.ProcessInfo(pid=2, ppid=1, name="suspicious", exe="/tmp/malware")
        result = self.engine.evaluate(proc, hash_known=True)
        self.assertGreaterEqual(result.score, 40)
        self.assertIn("suspicious path", result.reasons[0].lower())

    def test_keyboard_access(self) -> None:
        proc = self.ProcessInfo(pid=3, ppid=1, name="unknown", accesses_keyboard=True)
        result = self.engine.evaluate(proc, hash_known=True)
        self.assertGreaterEqual(result.score, 35)
        self.assertTrue(any("keyboard" in r.lower() for r in result.reasons))

    def test_unknown_hash(self) -> None:
        proc = self.ProcessInfo(pid=4, ppid=1, name="newproc", exe="/usr/bin/newproc")
        result = self.engine.evaluate(proc, hash_known=False)
        self.assertGreaterEqual(result.score, 20)

    def test_high_risk_combined(self) -> None:
        proc = self.ProcessInfo(
            pid=5, ppid=1, name="malware", exe="/tmp/malware",
            accesses_keyboard=True, is_root=True,
            cpu_percent=95.0, mem_mb=3000,
        )
        result = self.engine.evaluate(proc, hash_known=False)
        self.assertEqual(result.level, "high")
        self.assertGreaterEqual(result.score, 61)

    def test_score_clamped_to_100(self) -> None:
        proc = self.ProcessInfo(
            pid=6, ppid=1, name="superbad", exe="/tmp/bad",
            accesses_keyboard=True, is_root=True, is_zombie=True,
            is_orphan=True, respawn_count=10, cpu_percent=99, mem_mb=5000,
        )
        result = self.engine.evaluate(proc, hash_known=False)
        self.assertEqual(result.score, 100)


class TestDatabase(unittest.TestCase):
    """Tests for the SQLite database layer."""

    def setUp(self) -> None:
        from config import Config
        from database import Database
        self.tmpdir = tempfile.mkdtemp()
        cfg = Config(raw={"database": {"path": os.path.join(self.tmpdir, "test.db")}})
        self.db = Database(cfg)

    def test_insert_and_retrieve_event(self) -> None:
        event = {
            "timestamp": "2025-01-01T00:00:00",
            "pid": 1234, "ppid": 1, "name": "test", "exe": "/tmp/test",
            "cmdline": "/tmp/test", "username": "root", "cpu_percent": 10.0,
            "mem_mb": 50.0, "status": "running", "create_time": "2025-01-01",
            "exe_hash": "abc123", "risk_score": 40, "risk_level": "medium",
            "reason": "test reason", "action": "monitor",
        }
        rowid = self.db.insert_process_event(event)
        self.assertGreater(rowid, 0)

        events = self.db.get_recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["name"], "test")

    def test_insert_and_retrieve_alert(self) -> None:
        alert = {
            "timestamp": "2025-01-01T00:00:00", "pid": 1234,
            "process_name": "malware", "risk_score": 80,
            "risk_level": "high", "reason": "bad", "details": "{}",
        }
        self.db.insert_alert(alert)
        alerts = self.db.get_recent_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["process_name"], "malware")

    def test_hash_upsert_and_lookup(self) -> None:
        self.db.upsert_hash("aaa111", "/tmp/test")
        self.assertTrue(self.db.is_hash_known("aaa111"))
        self.assertFalse(self.db.is_hash_known("zzz999"))

    def test_stats(self) -> None:
        stats = self.db.get_stats()
        self.assertEqual(stats["total_events"], 0)
        self.assertEqual(stats["total_alerts"], 0)


class TestConfig(unittest.TestCase):
    """Tests for the configuration module."""

    def test_default_config(self) -> None:
        from config import load_config
        cfg = load_config()
        self.assertEqual(cfg.get("general", "app_name"), "IRONYX Process Guard")
        self.assertGreater(cfg.check_interval, 0)

    def test_risk_scores_loaded(self) -> None:
        from config import load_config
        cfg = load_config()
        scores = cfg.risk_scores
        self.assertIn("executable_in_tmp", scores)
        self.assertIn("keyboard_device_access", scores)


class TestRulesLoading(unittest.TestCase):
    """Tests for JSON rule file loading."""

    def test_suspicious_processes_json(self) -> None:
        path = Path(__file__).resolve().parent.parent / "rules" / "suspicious_processes.json"
        data = json.loads(path.read_text())
        self.assertIn("processes", data)
        self.assertIsInstance(data["processes"], list)

    def test_whitelist_json(self) -> None:
        path = Path(__file__).resolve().parent.parent / "rules" / "whitelist.json"
        data = json.loads(path.read_text())
        self.assertIn("whitelist", data)
        self.assertIn("systemd", data["whitelist"])

    def test_suspicious_paths_json(self) -> None:
        path = Path(__file__).resolve().parent.parent / "rules" / "suspicious_paths.json"
        data = json.loads(path.read_text())
        self.assertIn("paths", data)
        self.assertIn("/tmp", data["paths"])


if __name__ == "__main__":
    unittest.main()
