# PQC signature for audit logs

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import hashlib

from pqc_signature.dilithium_sign import sign_message
from pqc_signature.dilithium_verify import verify_signature
from utils.constants import ENCODING

# Sign a log entry (in-place)

def sign_log_entry(entry: dict, sk: bytes, pk: bytes) -> dict:
    entry_bytes = json.dumps(entry, sort_keys=True).encode(ENCODING)

    signature = sign_message(entry_bytes, sk)

    entry["signature"] = signature.hex()
    entry["public_key"]  = pk.hex()

    return entry

# Verify a signed log entry

def verify_log_entry(entry: dict) -> bool:
    sig = bytes.fromhex(entry["signature"])
    pk = bytes.fromhex(entry["public_key"])

    # Reconstruct the entry without signature fields
    entry_copy = dict(entry)
    del entry_copy["signature"]
    del entry_copy["public_key"]

    entry_bytes = json.dumps(entry_copy, sort_keys=True).encode(ENCODING)

    return verify_signature(entry_bytes, sig, pk)
