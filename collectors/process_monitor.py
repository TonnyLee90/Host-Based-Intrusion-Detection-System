"""
collect suspicious process
"""

import platform
import subprocess # running external commands and shell programs (ls, cat, ...)
from IDS.config import SUSPICIOUS_PROCESS_NAMES

def collect_processes() -> list[dict]:
    """
    Runs `ps aux` (POSIX) or `tasklist /fo csv` (Windows) and searches
    the raw text output for suspicious process names.  No resource metrics
    are captured in this path (psutil is required for that).
    """
    findings: list[dict] = []

    os_name = platform.system()
    try:
        if os_name == "Windows":
            cmd = ["tasklist", "/fo", "csv"] # format the output as CSV 
        else:
            # aux lists all processes with user, PID, CPU%, MEM%, command
            cmd = ["ps", "aux"]
            """
            a — show processes from all users, not just the current user
            u — show in user-friendly format (includes username, CPU%, memory%)
            x — include processes not attached to a terminal (background processes, daemons)
            """
        # text=True: Return strings instead of bytes and give up if the command takes more than 10 seconds
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout.lower()   # Case-insensitive search

        """
        output example
        user       pid %cpu %mem   command
        root         1  0.0  0.1   /sbin/init
        alice      423  0.2  1.4   python main.py
        bob        891  4.5  2.1   nmap -sv 192.168.1.0
        """
        for bad_name in SUSPICIOUS_PROCESS_NAMES: # bad_name = "nmap"
            if bad_name in output:
                findings.append({
                    "severity": "HIGH",
                    "category": "SUSPICIOUS_PROCESS",
                    "message":  f"Suspicious process detected: '{bad_name}'",
                })

    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  [INFO] Could not enumerate processes (subprocess fallback).")

    return findings
