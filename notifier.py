"""
IRONYX Process Guard — Notification System
===========================================

Sends desktop notifications (notify-py), terminal alerts (rich), and
optionally plays a sound when high-risk events are detected.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import Config, load_config

console = Console()

# Risk-level → colour mapping
_LEVEL_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "bold red",
}


class Notifier:
    """Multi-channel notification dispatcher."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or load_config()
        self.desktop_enabled: bool = self.cfg.get("notifications", "desktop", default=True)
        self.terminal_enabled: bool = self.cfg.get("notifications", "terminal", default=True)
        self.sound_enabled: bool = self.cfg.get("notifications", "sound", default=False)
        self._notifier = None

        if self.desktop_enabled:
            try:
                from notifypy import Notify
                self._notifier = Notify()
                self._notifier.application_name = "IRONYX Process Guard"
            except Exception:
                self.desktop_enabled = False

    # ── public API ──────────────────────────────────────────────────────────
    def notify(self, title: str, message: str, risk_level: str = "low",
               details: dict[str, Any] | None = None) -> None:
        """Send a notification through all enabled channels.

        Parameters
        ----------
        title:
            Short alert title.
        message:
            Human-readable description.
        risk_level:
            ``low``, ``medium``, or ``high`` — controls colour / urgency.
        details:
            Optional dict of extra fields shown in the terminal table.
        """
        if self.terminal_enabled:
            self._terminal_alert(title, message, risk_level, details)

        if self.desktop_enabled and self._notifier:
            self._desktop_alert(title, message, risk_level)

        if self.sound_enabled and risk_level == "high":
            self._play_sound()

    # ── terminal (rich) ─────────────────────────────────────────────────────
    def _terminal_alert(
        self,
        title: str,
        message: str,
        risk_level: str,
        details: dict[str, Any] | None,
    ) -> None:
        color = _LEVEL_COLORS.get(risk_level, "white")
        panel_content = f"[{color}]{message}[/{color}]"

        if details:
            table = Table(show_header=False, box=None, padding=(0, 1))
            for k, v in details.items():
                table.add_row(k, str(v))
            from io import StringIO
            buf = StringIO()
            tmp_console = Console(file=buf, width=60)
            tmp_console.print(table)
            panel_content += "\n" + buf.getvalue()

        panel = Panel(
            panel_content,
            title=f"[{color}]⚠ {title}[/{color}]",
            border_style=color,
            expand=False,
        )
        console.print(panel)

    # ── desktop ─────────────────────────────────────────────────────────────
    def _desktop_alert(self, title: str, message: str, risk_level: str) -> None:
        try:
            self._notifier.title = f"[{risk_level.upper()}] {title}"
            self._notifier.message = message
            self._notifier.send()
        except Exception:
            pass  # notifications are best-effort

    # ── sound ───────────────────────────────────────────────────────────────
    @staticmethod
    def _play_sound() -> None:
        try:
            import winsound  # type: ignore
            winsound.Beep(1000, 500)
        except Exception:
            pass  # sound is optional and platform-specific
