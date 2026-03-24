"""
Detection Engine
Signature-based detection of known-bad patterns.
  Rule 1 — Suspicious listening TCP ports  (ss / netstat)
  Rule 2 — New or modified setuid binaries (Linux only, find command)
"""
import re
import platform
import subprocess
from pathlib import Path
from IDS.config import SUSPICIOUS_PORTS, BASELINE_FILE

def run_signature_rules(raw_findings: list[dict]) -> list[dict]:
    """
    Apply signature rules and append any new findings to the list.

    Receives the merged collector findings, adds its own detections,
    and returns the augmented list.  The original list is not mutated.

    Args:
        raw_findings: Combined output from all three collectors.

    Returns:
        A new list containing all incoming findings plus any new ones
        discovered by the signature rules.
    """
    # Make a copy of input list (avoid modifying original data)
    copied_findings = list(raw_findings)

    # Run Rule 1: check suspicious ports and add results
    copied_findings.extend(_check_suspicious_ports())

    # Run Rule 2: check setuid binaries and add results
    copied_findings.extend(_check_setuid_binaries())

    return copied_findings

def _check_suspicious_ports() -> list[dict]:
    """
    Detect suspicious listening ports (e.g., backdoors).
    Uses system commands (ss or netstat).
    """
    findings: list[dict] = []
    OS = platform.system()
    try:
        if OS == "Linux":
            # -t TCP, -l listening only, -n numeric, -p show process name
            """
            LISTEN 0 128 0.0.0.0:22    0.0.0.0:*    users:(("sshd",pid=123))
            LISTEN 0 128 0.0.0.0:3306  0.0.0.0:*    users:(("mysqld",pid=456))
            """
            cmd = ["ss", "-tlnp"]
        else:
            # Windows: This retunrs network ports that are currently open and listening on the machine.
            cmd = ["netstat", "-an"]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        # .stdout returns: "LISTEN 0 128 0.0.0.0:22\nLISTEN 0 128 0.0.0.0:3306\n"
        for line in result.stdout.splitlines(): # Converts that string into a list:
            for port in SUSPICIOUS_PORTS:
                if (re.search(rf"\b{port}\b", line) and "LISTEN" in line.upper()):
                    findings.append({
                        "severity":  "HIGH",
                        "category":  "SUSPICIOUS_PORT",
                        "message":   (
                            f"Suspicious listener on port {port}: "
                            f"{line.strip()}"
                        ),
                        # This key is used to identify duplicate port alerts.
                        # so the system can avoid storing multiple alerts for the same port
                        "dedup_key": f"PORT:{port}",
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    return findings


def _check_setuid_binaries() -> list[dict]:
    """
    Normally: you run program → it runs as YOU
    With setuid: you run program → it runs as the FILE OWNER (often root)

    """
    findings: list[dict] = []

    if platform.system() != "Linux":
        return findings

    if not Path(BASELINE_FILE).exists():
        return findings

    try:
        result = subprocess.run(
            # -perm -4000 Find files that have the setuid permission enabled
            # -newer Finds files that were modified AFTER the BASELINE_FILE
             ["find", "/usr/bin", "-perm", "-4000", "-newer", BASELINE_FILE],
            capture_output=True, text=True, timeout=10,
        )

        for suid_path in result.stdout.strip().splitlines():
            if suid_path:   # Skip any empty lines
                findings.append({
                    "severity":  "CRITICAL",
                    "category":  "PRIVILEGE_ESCALATION",
                    "message":   f"New or modified setuid binary: {suid_path}",
                    "dedup_key": f"SUID:{suid_path}",
                })

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return findings
