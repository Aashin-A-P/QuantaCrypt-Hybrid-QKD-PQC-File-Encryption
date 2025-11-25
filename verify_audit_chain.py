# Minimal audit log integrity check

import json
import os
import hashlib
from utils.constants import AUDIT_LOG_FILE
from audit.pychain_anchor import verify_anchor

def verify_final_hash():
    if not os.path.exists(AUDIT_LOG_FILE):
        print("No audit.log found.")
        return

    with open(AUDIT_LOG_FILE, "r") as f:
        last_line = f.readlines()[-1]

    last_entry = json.loads(last_line)
    final_hash = last_entry["entry_hash"]

    # Now verify blockchain anchor
    anchor = verify_anchor()

    print("Final audit hash:", final_hash)
    print("Blockchain anchor result:", anchor)

if __name__ == "__main__":
    verify_final_hash()
