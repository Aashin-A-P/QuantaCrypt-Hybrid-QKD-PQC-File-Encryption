# Hybrid QKD + PQC key fusion

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.hashing import sha3_512

def derive_hybrid_key(qkd_key: bytes, pqc_secret: bytes) -> bytes:
    """
    Hybrid key = SHA3-512(QKD || PQC)
    Final output: 64 bytes (512-bit)
    """
    combined = qkd_key + pqc_secret
    return sha3_512(combined)
