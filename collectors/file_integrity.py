"""
File integrity monitoring using hashlib

Computes SHA-256 digests for every file in "config.WATCHED_FILES" and compares them against the saved baseline in "config.BASELINE_FILE."

Public functions:
    build_baseline()         — Hash watched files and persist to JSON.
    collect_file_integrity() — Diff current hashes against the baseline.
"""

import json
import hashlib
import IDS.config as config

def compute_sha256(filepath: str) -> str | None:
    """
    Stream a file in 64 KB chunks and return its SHA-256 hex digest.
    Returns None if the file is missing or unreadable (e.g. permission
    denied).

    input: /file1
    output: "9072d81a-464f-4390-99a2-369738c8a825"
    """
    try:
        hash_obj = hashlib.sha256()
        with open(filepath, "rb") as f:
            chunk = f.read(8192) # read 8192 bytes at a time
            while chunk:
                hash_obj.update(chunk)
                chunk = f.read(8192)
            return hash_obj.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def build_baseline() -> None:
    """
    Hash every file in WATCHED_FILES and save the results to BASELINE_FILE.
    baseline = {"/etc/passwd": "a1b2c3...", "/etc/hosts": "d4e5f6..."}
    {
        "/etc/passwd": "a1b2c3...",
        "/etc/hosts": "d4e5f6..."
    }
    """
    baseline: dict[str, str] = {}
    for filepath in config.WATCHED_FILES:
        digest = compute_sha256(filepath)
        if digest:
            baseline[filepath] = digest
            print(f"  [BASELINE] Hashed:   {filepath}")
        else:
            print(f"  [BASELINE] Skipped (unreadable): {filepath}")
    # converts the dictionary into a JSON string, with 2-space indentation and write it into the BASELINE_FILE
    with open(config.BASELINE_FILE, "w") as f:
        f.write(json.dumps(baseline, indent=2))
    
    print(f"\n  Baseline saved → {config.BASELINE_FILE}\n")

def collect_file_integrity() -> list[dict]:
    """
    Compare current file hashes against the saved baseline.

    Returns a list of finding dicts, each containing:
        severity  — "CRITICAL" (modified) or "MEDIUM" (missing)
        category  — "FILE_INTEGRITY"
        message   — description
    An empty list means all watched files match their baseline hashes.
    """
    findings: list[dict] = []
    # If no baseline exists yet, we have nothing to compare against
    try:
        with open(config.BASELINE_FILE) as f:
            baseline = json.loads(f.read()) # loads() converts json to dict, list,...
    except FileNotFoundError:
        print("  [INFO] No baseline found — run with --baseline first.")
        return findings

    # baseline = {"/etc/passwd": "a1b2c3...", "/etc/hosts": "d4e5f6..."}
    for filepath, original_hash in baseline.items():
        current_hash = compute_sha256(filepath)

        if current_hash is None:
            # File was present when the baseline was built but is now gone
            findings.append({
                "severity": "MEDIUM",
                "category": "FILE_INTEGRITY",
                "message":  f"Watched file is now missing: {filepath}",
            })

        elif current_hash != original_hash:
            # Content has changed since the baseline was recorded — possible tampering
            findings.append({
                "severity": "CRITICAL",
                "category": "FILE_INTEGRITY",
                "message":  (
                    f"File modified! {filepath}  "
                    f"(baseline: {original_hash[:8]}..., " # only the first 7 digits
                    f"current: {current_hash[:8]}...)"
                ),
            })
    return findings
