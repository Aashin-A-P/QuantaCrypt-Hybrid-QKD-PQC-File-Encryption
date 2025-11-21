# Tamper-evident audit log (hash-chained)
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import hashlib
import os

from utils.constants import AUDIT_LOG_FILE

# Compute SHA3-256 hash of log entry

def hash_entry(entry: dict) -> str:
    entry_bytes = json.dumps(entry, sort_keys=True).encode("utf-8")
    return hashlib.sha3_256(entry_bytes).hexdigest()

# Load last log entry (to chain hashes)

def get_last_log_hash() -> str:
    if not os.path.exists(AUDIT_LOG_FILE):
        return "0" * 64  # genesis hash

    with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        return "0" * 64

    last_record = json.loads(lines[-1])
    return last_record["entry_hash"]

# Create a new log entry

def create_log_entry(event_type: str, details: dict) -> dict:
    timestamp = time.time()

    entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "details": details,
        "prev_hash": get_last_log_hash()
    }

    entry_hash = hash_entry(entry)
    entry["entry_hash"] = entry_hash

    return entry

# Append entry to the audit log file

def append_log(entry: dict):
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
