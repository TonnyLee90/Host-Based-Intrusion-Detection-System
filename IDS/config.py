# File integrity
WATCHED_FILES: list[str] = [
    # Linux
    "/etc/passwd",
    "/etc/shadow",   
    "/etc/hosts",     
    "/etc/sudoers",
    # window
    r"C:\Users\a1003\OneDrive\Desktop\testing.txt"
]

# Path to the JSON file that stores the known-good SHA-256 hashes.
BASELINE_FILE: str = "ids_baseline.json"

# Authentication log scanning
AUTH_LOG_PATHS: list[str] = [
    "/var/log/auth.log",  # Debian / Ubuntu
    "/var/log/secure",    # RHEL / CentOS / Fedora
]

# Brute-force detection parameters.
FAILED_LOGIN_THRESHOLD: int      = 5   # Failures from one IP before alerting
FAILED_LOGIN_WINDOW_SECONDS: int = 60  # Rolling time window in seconds

# Signature rules 
# TCP port numbers that should never have an active listener on a clean system.
SUSPICIOUS_PORTS: list[int] = [4444, 1337, 6666, 31337, 8080, 9090]

# Process names associated with attack / reconnaissance tools.
SUSPICIOUS_PROCESS_NAMES: list[str] = [
    "nmap", "netcat", "nc", "ncat", "wireshark",
    "tcpdump", "hydra", "metasploit", "msfconsole",
    "john", "hashcat", "sqlmap", "aircrack-ng",
]

# Alert manager
# Duplicate alerts with the same dedup_key are suppressed within this window.
DEDUP_WINDOW_SECONDS: int = 60

# Path to the SQLite database file.
DB_FILE: str = "ids_alerts.db"

# Monitoring loop
# Seconds between scan cycles in --monitor / --web mode.
MONITOR_INTERVAL_SECONDS: int = 30

# Web dashboard
# TCP port the Flask server listens on.
FLASK_PORT: int = 5000
