import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets
import hashlib

# Secure random byte generator
def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

# SHA3-based Key Derivation Function (KDF)
def kdf(label: bytes, *parts: bytes, length: int = 32) -> bytes:
    h = hashlib.sha3_512()
    h.update(label)
    for p in parts:
        h.update(p)
    return h.digest()[:length]

# Simulated Kyber-like KeyGen
# pk = KDF("pk", sk)
# sk = random 32 bytes

def kyber_generate_keypair():
    sk = random_bytes(32)
    pk = kdf(b"pk", sk, length=32)
    return pk, sk

# Encapsulation
# r = random
# mask = KDF("mask", pk)
# ct = r XOR mask
# ss_sender = KDF("ss", pk, r)
def kyber_encapsulate(pk: bytes):
    r = random_bytes(32)
    mask = kdf(b"mask", pk, length=32)
    ct = bytes(a ^ b for a, b in zip(r, mask))  # masked ephemeral
    ss_sender = kdf(b"ss", pk, r, length=32)    # shared secret (sender)
    return ct, ss_sender

# Decapsulation
# mask = KDF("mask", pk)
# r' = ct XOR mask
# ss_receiver = KDF("ss", pk, r')
def kyber_decapsulate(ct: bytes, sk: bytes, pk: bytes):
    mask = kdf(b"mask", pk, length=32)
    r_prime = bytes(a ^ b for a, b in zip(ct, mask))
    ss_receiver = kdf(b"ss", pk, r_prime, length=32)
    return ss_receiver

# High-level PQC shared secret generator
# Returns: K_PQC (32 bytes), pk, ct
def generate_pqc_shared_secret(key_length_bytes: int = 32):
    pk, sk = kyber_generate_keypair()
    ct, ss_sender = kyber_encapsulate(pk)
    ss_receiver = kyber_decapsulate(ct, sk, pk)

    if ss_sender != ss_receiver:
        raise ValueError("Simulated KEM failure: shared secrets do not match.")

    # Derive final PQC key
    digest = hashlib.sha3_512(ss_sender).digest()
    K_PQC = digest[:key_length_bytes]

    return K_PQC, pk, ct

if __name__ == "__main__":
    print("=== Simulated Kyber-like KEM Test ===")

    K_PQC, pk, ct = generate_pqc_shared_secret()

    print("Public Key  (pk):", pk.hex())
    print("Ciphertext  (ct):", ct.hex())
    print("PQC Shared Secret (32 bytes):", K_PQC.hex())

    print("\nSimulation successful.")
