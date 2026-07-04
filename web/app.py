"""
IRONYX Process Guard — Flask Application Factory
=================================================

Creates a single Flask app that serves:
  - REST API endpoints at /api/* (real-time system data)
  - Crystal Glass dashboard at / (HTML/CSS/JS frontend)

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

from config import Config, load_config
from database import Database
from monitor import Monitor
from scheduler import ReportScheduler

# Paths
TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def create_app(monitor: Monitor | None = None, cfg: Config | None = None) -> Flask:
    """Create and configure the unified Flask application.

    Parameters
    ----------
    monitor:
        A running :class:`Monitor` instance. If None, a new one is created.
    cfg:
        Configuration object.

    Returns
    -------
    Flask
        Configured Flask app.
    """
    cfg = cfg or load_config()
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
    )
    monitor = monitor or Monitor(cfg)
    db = Database(cfg)
    reporter = ReportScheduler(cfg)

    # ── Serve frontend ──────────────────────────────────────────────────────

    @app.route("/")
    def index() -> Any:
        """Serve the Crystal Glass dashboard."""
        from flask import render_template
        return render_template("index.html")

    # ── API: System Overview ────────────────────────────────────────────────

    @app.route("/api/system")
    def api_system() -> Any:
        """Return real-time system information (CPU, RAM, disk, uptime)."""
        import psutil
        import platform
        import os
        from datetime import datetime

        boot_time = psutil.boot_time()
        uptime_seconds = int(datetime.now().timestamp() - boot_time)

        return jsonify({
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "distribution": _get_distro(),
            "kernel": platform.version()[:80],
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "cpu_per_core": _get_cpu_per_core(),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "used": psutil.virtual_memory().used,
                "percent": psutil.virtual_memory().percent,
            },
            "swap": {
                "total": psutil.swap_memory().total,
                "used": psutil.swap_memory().used,
                "percent": psutil.swap_memory().percent,
            },
            "disk": {
                "total": psutil.disk_usage("/").total,
                "used": psutil.disk_usage("/").used,
                "free": psutil.disk_usage("/").free,
                "percent": psutil.disk_usage("/").percent,
            },
            "uptime_seconds": uptime_seconds,
            "boot_time": datetime.fromtimestamp(boot_time).isoformat(),
            "load_average": _get_load_average(),
            "process_count": len(psutil.pids()),
        })

    # ── API: Processes ──────────────────────────────────────────────────────

    @app.route("/api/processes")
    def api_processes() -> Any:
        """Return current process snapshot with risk scores."""
        procs = monitor.get_processes()
        result = []
        for p in procs:
            # Compute risk score inline (same logic as detector)
            score = _compute_quick_risk(p)
            level = "low" if score <= 30 else "medium" if score <= 60 else "high"

            result.append({
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "exe": p.exe,
                "cmdline": p.cmdline[:200] if p.cmdline else "",
                "username": p.username,
                "cpu_percent": round(p.cpu_percent, 1),
                "mem_mb": round(p.mem_mb, 1),
                "status": p.status,
                "create_time": p.create_time,
                "exe_hash": p.exe_hash[:16] + "…" if p.exe_hash else "",
                "accesses_keyboard": p.accesses_keyboard,
                "is_root": p.is_root,
                "is_zombie": p.is_zombie,
                "is_orphan": p.is_orphan,
                "is_hidden": p.is_hidden,
                "connection_count": len(p.connections),
                "open_file_count": len(p.open_files),
                "risk_score": score,
                "risk_level": level,
            })

        # Sort by risk score descending
        result.sort(key=lambda x: x["risk_score"], reverse=True)
        return jsonify(result)

    # ── API: Alerts ─────────────────────────────────────────────────────────

    @app.route("/api/alerts")
    def api_alerts() -> Any:
        """Return recent alerts from the database."""
        limit = request.args.get("limit", 50, type=int)
        return jsonify(db.get_recent_alerts(limit=limit))

    @app.route("/api/alerts/acknowledge/<int:alert_id>", methods=["POST"])
    def api_ack_alert(alert_id: int) -> Any:
        """Acknowledge an alert."""
        db.acknowledge_alert(alert_id)
        return jsonify({"status": "ok", "id": alert_id})

    # ── API: Risk Summary ───────────────────────────────────────────────────

    @app.route("/api/risk")
    def api_risk() -> Any:
        """Return current risk summary."""
        procs = monitor.get_processes()
        high = medium = low = 0
        scored = []
        for p in procs:
            score = _compute_quick_risk(p)
            level = "low" if score <= 30 else "medium" if score <= 60 else "high"
            if level == "high":
                high += 1
            elif level == "medium":
                medium += 1
            else:
                low += 1
            scored.append({"pid": p.pid, "name": p.name, "score": score, "level": level})

        top = sorted(scored, key=lambda x: x["score"], reverse=True)[:15]
        return jsonify({
            "total_processes": len(procs),
            "high_risk": high,
            "medium_risk": medium,
            "low_risk": low,
            "top_risk": top,
        })

    # ── API: Keyboard Device Access ─────────────────────────────────────────

    @app.route("/api/keyboard")
    def api_keyboard() -> Any:
        """Return processes with keyboard device handles open."""
        return jsonify(monitor.get_keyboard_access())

    # ── API: Network ────────────────────────────────────────────────────────

    @app.route("/api/network")
    def api_network() -> Any:
        """Return current network connections."""
        return jsonify(monitor.get_network())

    # ── API: Stats ──────────────────────────────────────────────────────────

    @app.route("/api/stats")
    def api_stats() -> Any:
        """Return database statistics."""
        return jsonify(db.get_stats())

    # ── API: Dashboard Aggregate ────────────────────────────────────────────

    @app.route("/api/dashboard")
    def api_dashboard() -> Any:
        """Return aggregated dashboard data in a single call."""
        import psutil
        procs = monitor.get_processes()
        high = medium = low = 0
        for p in procs:
            score = _compute_quick_risk(p)
            if score > 60:
                high += 1
            elif score > 30:
                medium += 1
            else:
                low += 1

        return jsonify({
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=0),
                "memory_percent": psutil.virtual_memory().percent,
                "process_count": len(procs),
            },
            "risk": {"high": high, "medium": medium, "low": low},
            "stats": db.get_stats(),
            "recent_alerts": db.get_recent_alerts(limit=5),
            "keyboard_alerts": [
                k for k in monitor.get_keyboard_access() if not k.get("is_known", True)
            ],
        })

    # ── API: Risk History ───────────────────────────────────────────────────

    @app.route("/api/history/<int:pid>")
    def api_history(pid: int) -> Any:
        """Return risk history for a specific PID."""
        return jsonify(db.get_risk_history(pid))

    # ── API: Report ─────────────────────────────────────────────────────────

    @app.route("/api/report")
    def api_report() -> Any:
        """Generate a report on-demand."""
        fmt = request.args.get("format", "json")
        files = reporter.generate(fmt=fmt)
        return jsonify({"files": files})

    # ── API: Filesystem Events ──────────────────────────────────────────────

    @app.route("/api/filesystem")
    def api_filesystem() -> Any:
        """Return recent filesystem events from the database."""
        events = db.get_recent_events(limit=50)
        # Filter for ones that have filesystem-related reasons
        return jsonify(events)

    # ── Static files fallback ───────────────────────────────────────────────

    @app.route("/health")
    def health() -> Any:
        """Health check endpoint."""
        return jsonify({"status": "healthy", "monitor": "active"})

    return app


# ── Helpers ─────────────────────────────────────────────────────────────────

def _compute_quick_risk(p: Any) -> int:
    """Quick inline risk score for API responses."""
    score = 0
    if p.exe and p.exe.startswith(("/tmp", "/dev/shm", "/var/tmp")):
        score += 40
    if p.accesses_keyboard:
        score += 35
    if p.is_root and p.exe and p.exe.startswith(("/tmp", "/dev/shm", "/var/tmp")):
        score += 25
    if p.is_zombie:
        score += 10
    if p.is_orphan:
        score += 10
    if p.is_hidden:
        score += 15
    if p.cpu_percent > 90:
        score += 15
    if p.mem_mb > 2048:
        score += 15
    if p.respawn_count >= 5:
        score += 25
    return min(score, 100)


def _get_distro() -> str:
    """Return the Linux distribution name."""
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Unknown"


def _get_cpu_per_core() -> list[float]:
    """Return per-core CPU usage percentages."""
    import psutil
    try:
        return [round(c, 1) for c in psutil.cpu_percent(interval=0.5, percpu=True)]
    except Exception:
        return []


def _get_load_average() -> list[float]:
    """Return the 1/5/15-minute load averages."""
    import os
    try:
        load = os.getloadavg()
        return [round(l, 2) for l in load]
    except (OSError, AttributeError):
        return [0.0, 0.0, 0.0]
