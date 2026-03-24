# HIDS v2 — Host-Based Intrusion Detection System

A Python-based host intrusion detection system that monitors your local machine for signs of compromise across four pipeline layers: collection, detection, alerting, and output.

---

## Requirements

- Python 3.10+
- pip

---

## Installation

**1. Clone the project**
```bash
git clone https://github.com/yourname/hids.git
cd hids
```

**2. Create a virtual environment (recommended)**

Linux / macOS:
```bash
python -m venv venv
source venv/bin/activate
```

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

---

## Quick Start

### Step 1 — Build the file-integrity baseline
Run this **once** on a clean system before monitoring:

Linux / macOS:
```bash
sudo python main.py baseline
```

Windows:
```bash
python main.py baseline
```

> **Note:** `sudo` is needed on Linux to read protected files like `/etc/shadow`. Unreadable files are skipped gracefully.

### Step 2 — Run a single scan
```bash
python main.py scan
```

### Step 3 — Continuous monitoring
```bash
python main.py monitor
```
Scans every 30 seconds. Press **Ctrl+C** to stop.

### Step 4 — Monitoring + web dashboard
```bash
python main.py web
```
Then open **http://localhost:5000** in a browser. JSON API available at `/api/alerts`.

---

## All Commands

| Command | Description |
|---|---|
| `python main.py baseline` | Build / rebuild the file-integrity baseline |
| `python main.py scan` | Run a single scan and exit |
| `python main.py monitor` | Continuous scanning loop (Ctrl+C to stop) |
| `python main.py web` | Continuous scanning + Flask web dashboard |
| `python main.py --help` | Show all available commands |

---

## Testing on Windows

The default `WATCHED_FILES` paths (`/etc/passwd` etc.) are Linux-only. For Windows, add a local file to `IDS/config.py`:

```python
WATCHED_FILES: list[str] = [
    r"C:\Users\youruser\Desktop\test_watch.txt",
]
```

Then trigger an alert:
```bash
# 1. Create the test file
echo original content > test_watch.txt

# 2. Build baseline
python main.py baseline

# 3. Modify the file
echo tampered >> test_watch.txt

# 4. Scan — should show a CRITICAL FILE_INTEGRITY alert
python main.py scan
```

---

## Project Structure

```
hids/
├── main.py                    CLI entry point (Typer)
├── requirements.txt
├── IDS/
│   ├── config.py              All tunable constants
│   ├── alert_manager.py       SQLite persistence + dedup
│   └── scanner.py             Scan orchestrator
├── collectors/                Layer 1 — gather raw telemetry
│   ├── file_integrity.py      SHA-256 baseline + tamper detection
│   ├── process_monitor.py     psutil process scan
│   └── log_parser.py          Auth log + brute-force detection
├── detections/                Layer 2 — classify findings
│   └── signature_rules.py     Known-bad ports + process names
└── output/                    Layer 3 — output channels
    ├── terminal_ui.py         Rich colour-coded table
    └── web_dashboard.py       Flask HTML dashboard
```

---

## Configuration

All settings are in `IDS/config.py`:

| Constant | Default | Description |
|---|---|---|
| `WATCHED_FILES` | `/etc/passwd`, `/etc/hosts`... | Files tracked for integrity |
| `FAILED_LOGIN_THRESHOLD` | `5` | Failed logins before brute-force alert |
| `FAILED_LOGIN_WINDOW_SECONDS` | `60` | Rolling window for login failures (s) |
| `SUSPICIOUS_PORTS` | `4444, 1337, 6666`... | Ports that trigger HIGH alerts |
| `SUSPICIOUS_PROCESS_NAMES` | `nmap, netcat, hydra`... | Process names that trigger alerts |
| `MONITOR_INTERVAL_SECONDS` | `30` | Seconds between scans |
| `FLASK_PORT` | `5000` | Web dashboard port |

---

## Output Files

| File | Created by | Contents |
|---|---|---|
| `ids_baseline.json` | `baseline` command | Known-good SHA-256 hashes |
| `ids_alerts.db` | First scan | SQLite alert database |

---

## Alert Severity Levels

| Severity | When raised |
|---|---|
| `CRITICAL` | Watched file modified since baseline |
| `HIGH` | Brute-force attempt, suspicious port or process |
| `MEDIUM` | Watched file is now missing |
| `LOW` | Reserved for future use |

---

## Dependencies

| Package | Used for | Without it |
|---|---|---|
| `psutil` | Process & port scanning | Falls back to subprocess |
| `rich` | Colour terminal output | Falls back to plain print() |
| `flask` | Web dashboard | Dashboard won't start |
| `typer` | CLI commands | Required — must install |
