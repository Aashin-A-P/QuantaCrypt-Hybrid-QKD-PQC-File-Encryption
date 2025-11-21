import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib

# Verify signature:
#   expected = SHA3-512(pk || message)
#   return expected == signature

def verify_signature(message: bytes, signature: bytes, pk: bytes) -> bool:
    h = hashlib.sha3_512()
    h.update(pk)
    h.update(message)
    expected = h.digest()
    return expected == signature

def verify_file_signature(file_bytes: bytes, signature: bytes, pk: bytes):
    return verify_signature(file_bytes, signature, pk)
