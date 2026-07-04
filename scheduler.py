"""
IRONYX Process Guard — Report Scheduler
========================================

Generates periodic or on-demand reports in JSON, CSV, HTML, and PDF
formats from the database.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config import Config, load_config
from database import Database
from logger import get_app_logger

log = get_app_logger()


class ReportScheduler:
    """Generate and export security reports."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or load_config()
        self.db = Database(self.cfg)
        self.output_dir = Path(self.cfg.report_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, fmt: str = "all") -> list[str]:
        """Generate report(s) in the specified format.

        Parameters
        ----------
        fmt:
            ``json``, ``csv``, ``html``, ``pdf``, or ``all``.

        Returns
        -------
        list[str]
            Paths to generated report files.
        """
        data = self._collect_data()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        formats = ["json", "csv", "html", "pdf"] if fmt == "all" else [fmt]
        files: list[str] = []

        for f in formats:
            try:
                method = getattr(self, f"_export_{f}")
                path = method(data, timestamp)
                files.append(path)
                log.info("Generated %s report: %s", f.upper(), path)
            except Exception as exc:
                log.error("Failed to generate %s report: %s", f, exc)

        return files

    def _collect_data(self) -> dict[str, Any]:
        """Collect all data for the report."""
        return {
            "generated_at": datetime.now().astimezone().isoformat(),
            "stats": self.db.get_stats(),
            "recent_events": self.db.get_recent_events(limit=200),
            "recent_alerts": self.db.get_recent_alerts(limit=100),
        }

    # ── JSON ────────────────────────────────────────────────────────────────
    def _export_json(self, data: dict[str, Any], ts: str) -> str:
        path = self.output_dir / f"report_{ts}.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return str(path)

    # ── CSV ─────────────────────────────────────────────────────────────────
    def _export_csv(self, data: dict[str, Any], ts: str) -> str:
        path = self.output_dir / f"report_{ts}.csv"
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "Timestamp", "PID", "Name", "Exe", "User",
                "Risk Score", "Risk Level", "Reason",
            ])
            for evt in data["recent_events"]:
                writer.writerow([
                    evt.get("timestamp", ""), evt.get("pid", ""),
                    evt.get("name", ""), evt.get("exe", ""),
                    evt.get("username", ""), evt.get("risk_score", ""),
                    evt.get("risk_level", ""), evt.get("reason", ""),
                ])
        return str(path)

    # ── HTML ────────────────────────────────────────────────────────────────
    def _export_html(self, data: dict[str, Any], ts: str) -> str:
        path = self.output_dir / f"report_{ts}.html"
        html = self._build_html(data)
        path.write_text(html, encoding="utf-8")
        return str(path)

    def _build_html(self, data: dict[str, Any]) -> str:
        stats = data["stats"]
        events = data["recent_events"][:50]
        alerts = data["recent_alerts"][:50]

        events_rows = "".join(
            f"<tr><td>{e.get('timestamp','')}</td><td>{e.get('pid','')}</td>"
            f"<td>{e.get('name','')}</td><td>{e.get('risk_score',0)}</td>"
            f"<td>{e.get('risk_level','')}</td><td>{e.get('reason','')}</td></tr>"
            for e in events
        )
        alert_rows = "".join(
            f"<tr><td>{a.get('timestamp','')}</td><td>{a.get('process_name','')}</td>"
            f"<td>{a.get('risk_score',0)}</td><td>{a.get('risk_level','')}</td>"
            f"<td>{a.get('reason','')}</td></tr>"
            for a in alerts
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IRONYX Process Guard — Security Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; margin: 2rem; background: #1a1a2e; color: #e0e0e0; }}
  h1 {{ color: #e94560; }} h2 {{ color: #0f3460; color: #4ea8de; }}
  .stats {{ display: flex; gap: 1rem; margin: 1rem 0; }}
  .stat-card {{ background: #16213e; padding: 1rem 2rem; border-radius: 8px; text-align: center; }}
  .stat-card .num {{ font-size: 1.8rem; font-weight: bold; color: #e94560; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #333; }}
  th {{ background: #16213e; color: #4ea8de; }}
  .high {{ color: #ff4444; }} .medium {{ color: #ffaa00; }} .low {{ color: #44ff44; }}
</style>
</head>
<body>
<h1>IRONYX Process Guard — Security Report</h1>
<p>Generated: {data['generated_at']}</p>
<div class="stats">
  <div class="stat-card"><div class="num">{stats['total_events']}</div>Total Events</div>
  <div class="stat-card"><div class="num">{stats['total_alerts']}</div>Total Alerts</div>
  <div class="stat-card"><div class="num">{stats['high_risk_alerts']}</div>High Risk</div>
  <div class="stat-card"><div class="num">{stats['known_hashes']}</div>Known Hashes</div>
</div>
<h2>Recent Alerts</h2>
<table><tr><th>Time</th><th>Process</th><th>Score</th><th>Level</th><th>Reason</th></tr>
{alert_rows}</table>
<h2>Recent Process Events</h2>
<table><tr><th>Time</th><th>PID</th><th>Name</th><th>Score</th><th>Level</th><th>Reason</th></tr>
{events_rows}</table>
</body></html>"""

    # ── PDF ─────────────────────────────────────────────────────────────────
    def _export_pdf(self, data: dict[str, Any], ts: str) -> str:
        """Generate a PDF report using reportlab."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        )

        path = self.output_dir / f"report_{ts}.pdf"
        doc = SimpleDocTemplate(str(path), pagesize=A4,
                                topMargin=50, bottomMargin=50)
        styles = getSampleStyleSheet()
        story: list[Any] = []

        story.append(Paragraph("IRONYX Process Guard — Security Report", styles["Title"]))
        story.append(Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]))
        story.append(Spacer(1, 20))

        # Stats table
        stats = data["stats"]
        stats_data = [
            ["Metric", "Value"],
            ["Total Events", str(stats["total_events"])],
            ["Total Alerts", str(stats["total_alerts"])],
            ["High Risk Alerts", str(stats["high_risk_alerts"])],
            ["Unacknowledged", str(stats["unacknowledged_alerts"])],
            ["Known Hashes", str(stats["known_hashes"])],
        ]
        t = Table(stats_data, colWidths=[200, 100])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))

        # Alerts table
        story.append(Paragraph("Recent Alerts", styles["Heading2"]))
        alert_data = [["Time", "Process", "Score", "Level", "Reason"]]
        for a in data["recent_alerts"][:30]:
            alert_data.append([
                str(a.get("timestamp", ""))[:19],
                str(a.get("process_name", "")),
                str(a.get("risk_score", 0)),
                str(a.get("risk_level", "")),
                str(a.get("reason", ""))[:60],
            ])
        t2 = Table(alert_data, colWidths=[100, 80, 40, 50, 250])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e94560")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        story.append(t2)

        doc.build(story)
        return str(path)
