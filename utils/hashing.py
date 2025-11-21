# ==========================================================
# hashing.py  — SHA3 utilities used across the system
# ==========================================================
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import hmac

# ----------------------------------------------------------
# SHA3-256
# ----------------------------------------------------------
def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

# ----------------------------------------------------------
# SHA3-512
# ----------------------------------------------------------
def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

# ----------------------------------------------------------
# HMAC using SHA3-256
# ----------------------------------------------------------
def hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha3_256).digest()

# ----------------------------------------------------------
# Generate hash for audit logs, file metadata, key fusion, etc.
# ----------------------------------------------------------
def hash_for_metadata(*args: bytes) -> bytes:
    """
    Combines multiple byte sequences and hashes them.
    """
    combined = b"".join(args)
    return sha3_256(combined)
