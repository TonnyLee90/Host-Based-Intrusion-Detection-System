"""
Central alert dispatcher.  Every finding from every detection engine is
routed through alert() here.

Responsibilities:
  1. Deduplicate — suppress repeat events within DEDUP_WINDOW_SECONDS.
  2. Persist     — insert each unique alert into the SQLite database.
  3. Log         — append a plain-text line to ids_alerts.log.
  4. Emit        — print to stdout (Rich-coloured if available, else plain).
  5. Buffer      — keep an in-memory list for the terminal UI summary.
"""
import sqlite3
import threading
import time
from datetime import datetime
from IDS.config import DB_FILE, DEDUP_WINDOW_SECONDS

# ── In-memory alert buffer (cleared at the start of each scan cycle) ──────────
# The terminal UI reads this list to build its summary table.
runtime_alerts: list[dict] = []

# SQLite setup
def _init_db() -> sqlite3.Connection:
    """
    Open (or create) the SQLite database and ensure the alerts table exists.
    check_same_thread=False allows the multi-thread access
    """
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,    -- ISO-8601 timestamp string
            severity  TEXT NOT NULL,    -- LOW / MEDIUM / HIGH / CRITICAL
            category  TEXT NOT NULL,    -- e.g. FILE_INTEGRITY
            message   TEXT NOT NULL,    -- Human-readable description
            dedup_key TEXT              -- Fingerprint used for deduplication
        )
    """)
    conn.commit()
    return conn

# Module-level shared connection + write lock
_db_conn = _init_db()
_db_lock = threading.Lock()   # Lock to prevent concurrent DB writes
"""
Thread A enters → locks DB
Thread B tries → must WAIT
Thread A finishes → unlocks
Thread B continues

# without lock
Thread A: INSERT INTO alerts ...
Thread B: INSERT INTO alerts ...
At same time → SQLite error / corrupted writes
"""
_dedup_cache: dict[str, float] = {} # Stores last time each alert was seen

def alert(severity: str, category: str, message: str, dedup_key: str | None = None) -> None:
    """
    ## alert("HIGH", "FILE_INTEGRITY", "passwd file was modified")
    1. Prevents duplication
    2. Stores alert in database
    3. Writes to log file
    4. Stores in memory for UI
    5. Prints to console
    """
    # Build a default dedup key if the caller didn't supply one
    if dedup_key is None:
        dedup_key = f"{severity}:{category}:{message[:80]}"
    now = time.time()
    # 1. duplication check
    # If the same alert happened recently → ignore it
    if dedup_key in _dedup_cache:
        # Ignore duplicate alert within time window
        if now - _dedup_cache[dedup_key] < DEDUP_WINDOW_SECONDS:
            return

    _dedup_cache[dedup_key] = now # Update last seen time

    # 2. Create alert line
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # "2026-03-23 14:30:01"
    line = f"[{ts}] [{severity}] [{category}] {message}"

    # 3. save it to SQLite
    """
    | id | time    | severity | category       | message       |...
    | -- | ------- | -------- | -------------- | ------------- |---
    | 1  | 2026... | HIGH     | FILE_INTEGRITY | file modified |...
    """
    with _db_lock:
        """
        # Insert a new alert record into the SQLite database.
        # The SQL statement defines which columns to fill in the "alerts" table.
        # The '?' are used for parameterized queries, which safely substitute the actual values (time, severity, ...)
        """
        _db_conn.execute(
            "INSERT INTO alerts (ts, severity, category, message, dedup_key) "
            "VALUES (?, ?, ?, ?, ?)",
            (ts, severity, category, message, dedup_key)
        )
        _db_conn.commit()

    # 4. write to log file
    with open("ids_alerts.log", "a") as f:
        f.write(line + "\n") # [2026-03-23 14:30:01] [HIGH] [FILE_INTEGRITY] Critical file /etc/passwd was modified

    # Store in memory for terminal UI summary
    runtime_alerts.append({
        "time": ts, 
        "severity": severity,
        "category": category, 
        "message": message,
    })

    # Print to console
    print(line)

def get_db_connection() -> tuple[sqlite3.Connection, threading.Lock]:
    """
    Return the shared (connection, lock) pair so the Flask dashboard can
    query the database without opening a separate connection.
    """
    return _db_conn, _db_lock

# Clear the in-memory buffer at the start of each new scan cycle.
def clear_runtime_alerts() -> None:
    runtime_alerts.clear()
