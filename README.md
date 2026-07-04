# 🛡 IRONYX Process Guard

**A professional-grade Linux Endpoint Detection and Response (EDR) system with a Crystal Glass web dashboard.**

Built for Garuda Linux / Arch Linux. Monitors processes, filesystem, network, keyboard devices, system integrity, and persistence mechanisms in real time — all through a beautiful web interface.

> ⚠️ **Defensive-only tool.** Detects and reports suspicious behavior. Does NOT capture keystrokes, record passwords, inject code, or escalate privileges.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the unified application
python run.py

# 3. Open http://127.0.0.1:5555 in your browser
```

For full process visibility (seeing all users' processes, keyboard FDs):
```bash
sudo python run.py
```

---

## Features

- **Real-time Process Monitor** — All running processes with PID, CPU, RAM, user, hash, risk score
- **Filesystem Watcher** — Monitors /tmp, /dev/shm, ~/.cache, ~/.config for new executables
- **Keyboard Device Monitor** — Detects which processes have /dev/input/event* handles open (keylogger detection without capturing keystrokes)
- **Network Monitor** — Per-process TCP/UDP connections, suspicious ports, blacklisted IPs
- **Integrity Monitor** — SHA-256 baseline for critical system binaries (sudo, sshd, bash, etc.)
- **Persistence Detection** — Monitors systemd services, autostart entries, cron jobs
- **Risk Engine** — Scores every process 0–100 with configurable weighted rules
- **Crystal Glass Dashboard** — Dark-mode web UI with live charts, tables, search, and filters
- **REST API** — Full JSON API for integration with other tools
- **Reports** — Generate JSON, CSV, HTML, and PDF security reports
- **SQLite Database** — All events, alerts, and hashes persisted
- **Rotating Logs** — Separate app, security, and alert log streams

---

## Architecture

```
run.py (Entry Point)
  ├── Monitor (background thread)
  │     ├── ProcessMonitor (psutil)
  │     ├── FilesystemMonitor (watchdog)
  │     ├── NetworkMonitor
  │     ├── InputDeviceMonitor (keyboard FD detection)
  │     ├── ServiceMonitor (systemd)
  │     ├── StartupMonitor (autostart + cron)
  │     └── IntegrityMonitor (SHA-256 baseline)
  │
  └── Flask App (web/app.py)
        ├── /api/* — REST API endpoints (real-time data)
        └── / — Crystal Glass dashboard (HTML/CSS/JS)
```

---

## Usage

### Unified Dashboard (Default)
```bash
python run.py                    # Start on http://127.0.0.1:5555
sudo python run.py               # Root for full visibility
python run.py --port 8080        # Custom port
python run.py --host 0.0.0.0     # Listen on all interfaces
python run.py --no-browser       # Don't auto-open browser
```

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/system` | Real-time system info (CPU, RAM, disk, uptime) |
| `GET /api/processes` | All running processes with risk scores |
| `GET /api/alerts` | Recent security alerts |
| `GET /api/risk` | Risk summary (high/medium/low counts) |
| `GET /api/keyboard` | Processes with keyboard device access |
| `GET /api/network` | Active network connections |
| `GET /api/stats` | Database statistics |
| `GET /api/dashboard` | Aggregated dashboard data |
| `GET /api/history/<pid>` | Risk history for a PID |
| `POST /api/alerts/acknowledge/<id>` | Acknowledge an alert |
| `GET /api/report?format=pdf` | Generate a report |

---

## Risk Engine

| Rule | Points |
|------|--------|
| Executable in /tmp | +40 |
| Keyboard device access | +35 |
| Runs as root unexpectedly | +25 |
| Rapid respawn | +25 |
| Network beacon | +20 |
| Unknown hash | +20 |
| Hidden file | +15 |
| High CPU (>90%) | +15 |
| Memory anomaly (>2GB) | +15 |
| Zombie process | +10 |
| Orphan process | +10 |

**Levels:** Low (0-30) · Medium (31-60) · High (61-100)

---

## Configuration

Edit `config.yaml` to customize monitoring paths, risk scores, thresholds, and more.

---

## Testing

```bash
pytest tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE)
