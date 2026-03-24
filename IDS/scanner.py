"""
ties all four layers together.
Collectors  →  Detection  →  Alert manager  →  Output
Imported by main.py and called once per scan cycle.

"""

from datetime import datetime
from collectors.file_integrity import collect_file_integrity
from collectors.process_monitor import collect_processes
from collectors.log_parser import collect_auth_logs
from detections.signature_rules import run_signature_rules
from IDS.alert_manager import alert, clear_runtime_alerts
from output.terminal_ui import render_terminal_ui

# Scan counter — incremented each call, passed to the terminal UI
_scan_num: int = 0

def run_scan() -> None:
    """
    Execute one complete scan cycle through all four layers:
        1. Collectors    — gather raw telemetry
        2. Signature rules — apply known-bad pattern rules
        3. Alert manager   — dispatch every finding to all output channels
        4. Terminal UI     — render the per-scan summary table
    """
    global _scan_num
    _scan_num += 1

    # Clear the in-memory alert buffer so the terminal UI only shows findings from this cycle, not accumulated from previous ones.
    clear_runtime_alerts()

    # Print a visual separator between scan cycles
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'─' * 55}")
    print(f"  Scan #{_scan_num}  —  {ts}")
    print(f"{'─' * 55}")

    # 1. Run all three collectors 
    print("  [*] Collector: file integrity…")
    findings = collect_file_integrity()

    print("  [*] Collector: processes…")
    findings += collect_processes()

    print("  [*] Collector: auth logs…")
    findings += collect_auth_logs()

    # 2. Apply signature rules 
    print("  [*] Detection: signature rules…")
    findings = run_signature_rules(findings)

    # 3. Dispatch all findings through the alert manager 
    for finding in findings:
        alert(
            severity  = finding["severity"],
            category  = finding["category"],
            message   = finding["message"],
            dedup_key = finding.get("dedup_key"),
        )

    # 5. Render the terminal UI summary table 
    render_terminal_ui(_scan_num)
