import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import secrets
import hashlib

# Generate keypair
# sk = random 32 bytes
# pk = SHA3-256(sk)

def generate_sig_keypair():
    sk = secrets.token_bytes(32)
    pk = hashlib.sha3_256(sk).digest()
    return pk, sk


# Sign message using:
#   sig = SHA3-512(pk || message)
def sign_message(message: bytes, sk: bytes):
    pk = hashlib.sha3_256(sk).digest()
    h = hashlib.sha3_512()
    h.update(pk)
    h.update(message)
    sig = h.digest()
    return sig


# Helper wrapper: sign packed encrypted file
def sign_file_bytes(file_bytes: bytes, sk: bytes):
    return sign_message(file_bytes, sk)
