# Host-Based Intrusion Detection System on Linux (HIDS)

A Basic Python-based host intrusion detection system that monitors your local machine for signs of compromise.

---

## Installation

**1. Clone the project**
```bash
git clone https://github.com/TonnyLee90/Host-Based-Intrusion-Detection-System.git
cd Host-Based-Intrusion-Detection-System
```

**2. Create a virtual environment**

Linux / macOS:
```bash
python -m venv venv
source venv/bin/activate
```
**3. Install dependencies**
```bash
pip install -r requirements.txt
```
---

## Quick Start

### Step 1 — Build the file-integrity baseline
Run this **once** on a clean system before monitoring

Linux / macOS:
```bash
sudo python main.py baseline
```
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

## Core Flow
```
                        ┌─────────────────────┐
                        │       main.py       │
                        └─────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — Collectors                                           │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐ │
│  │  File integrity  │  │   Log parser     │  │Process monitor │ │
│  └──────────────────┘  └──────────────────┘  └────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                │                │               │
                └────────────────│───────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2 — Detection                                            │
│                  ┌──────────────────────────┐                   │
│                  │     Signature rules      │                   │
│                  └──────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────┐
                  │      Alert manager       │
                  └──────────────────────────┘
                                 │
                ┌────────────────┼───────────────┐
                ▼                ▼               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3 — Output                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐ │
│  │   Terminal UI    │  │  Web dashboard   │  │File & database │ │
│  └──────────────────┘  └──────────────────┘  └────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---
## Configuration

All settings are in `IDS/config.py`

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
| `LOW` | informational alerts|

---

## Dependencies

| Package | Used for | Without it |
|---|---|---|
| `psutil` | Process & port scanning | Falls back to subprocess |
| `flask` | Web dashboard | Dashboard won't start |
| `typer` | CLI commands | Required — must install |
