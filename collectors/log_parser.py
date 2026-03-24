"""
Authentication log parsing using re and open().

Scans the log files listed in config.AUTH_LOG_PATHS for failed SSH password events.  
Groups failures by source IP and flags any IP that breaches the brute-force threshold within the rolling time window.

Public function:
    collect_auth_logs() → list[dict]
"""

import re
import time
from collections import defaultdict
import IDS.config as config

#   "Failed password for root from 10.0.0.1 port 22 ssh2" 
#   "Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2"
# Capture group 1 = source IP address.
_FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\S+) port \d+"
)

def collect_auth_logs() -> list[dict]:
    """
    Scan authentication log files for brute-force login patterns.
    one per source IP that exceeded FAILED_LOGIN_THRESHOLD failures within FAILED_LOGIN_WINDOW_SECONDS.
    Returns an empty list if no log files are readable or no threshold is breached.
    """
    findings: list[dict] = []
    """
    failed_login_attempts = {"192.162.15.25" : "[12/30/2001-19:30, 12/30/2001-19:31, 12/30/2001-19:32]"}
        - Key: (e.g., a username or an IP address from your logs).
        - Value: A list of floats (e.g., timestamps of login failures).
    """
    for log_path in config.AUTH_LOG_PATHS:
        # defaultdict(list) does this behind the scenes 
        # failed_login_attempts["192.168.1.1"] = list()
        failed_login_attempts: dict[str, list[float]] = defaultdict(list) # like a regular dict, but with one key difference — if try to access a key that doesn't exist yet, instead of raising a KeyError it automatically creates that key with an empty list [] as its default value.
        try:
            # earch log for failed login line by line in the file
            with open(log_path) as f:
                for line in f:
                    match = _FAILED_LOGIN_PATTERN.search(line)
                    if match:
                        source_ip = match.group(1)
                        failed_login_attempts[source_ip].append(time.time())       
        except FileNotFoundError:
            print("[INFO] No file found ")
        except PermissionError:
            print(f"  [INFO] No read access to {log_path} — try sudo.")

        now = time.time()
        for ip, timestamps in failed_login_attempts.items():
            recent_attempts = []
            for t in timestamps:
                if now - t <= config.FAILED_LOGIN_WINDOW_SECONDS:
                    recent_attempts.append(t) # [17:30, 17:31, 17:32]

            if len(recent_attempts) >= config.FAILED_LOGIN_THRESHOLD: # numbers of failed login >= threshold
                findings.append({
                    "severity":  "HIGH",
                    "category":  "BRUTE_FORCE",
                    "message":   (
                        f"{len(recent_attempts)} failed logins from {ip} "
                        f"in the last {config.FAILED_LOGIN_WINDOW_SECONDS}s — "
                        f"possible brute-force attack"
                    )
                })
    return findings
