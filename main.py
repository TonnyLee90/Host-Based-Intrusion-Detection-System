"""
Usage:
    python main.py                # single scan, then exit
    python main.py --baseline     # build / rebuild file-integrity baseline
    python main.py --monitor      # continuous scan loop (Ctrl+C to stop)
    python main.py --web          # continuous scan + Flask dashboard on :5000
"""
import time
import typer

from IDS.scanner import run_scan
from collectors.file_integrity import build_baseline
from output.web_dashboard import start_web_dashboard
from IDS.config import MONITOR_INTERVAL_SECONDS

app = typer.Typer(help="HIDS v2 — psutil · SQLite · Rich · Flask")

@app.command()
def scan():
    """Run a single scan and exit."""
    run_scan()

@app.command()
def baseline():
    """Generate a new file-integrity baseline and exit."""
    typer.echo("[*] Building file-integrity baseline…")
    build_baseline()

@app.command()
def monitor():
    """Continuous monitoring mode (scan every N seconds)."""
    typer.echo(f"[*] Monitoring — scan every {MONITOR_INTERVAL_SECONDS}s (Ctrl+C to stop)\n")
    try:
        while True:
            run_scan()
            time.sleep(MONITOR_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        typer.echo("\n[*] Monitoring stopped.")

@app.command()
def web():
    """Start the Flask dashboard alongside continuous monitoring."""
    start_web_dashboard()
    typer.echo(f"[*] Monitoring — scan every {MONITOR_INTERVAL_SECONDS}s (Ctrl+C to stop)\n")
    try:
        while True:
            run_scan()
            time.sleep(MONITOR_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        typer.echo("\n[*] Monitoring stopped.")


if __name__ == "__main__":
    app()