import secrets
import hashlib

def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

def kdf(label: bytes, *parts: bytes, length: int = 32) -> bytes:
    h = hashlib.sha3_512()
    h.update(label)
    for p in parts:
        h.update(p)
    return h.digest()[:length]


def kem_keygen():
    """
    Toy Kyber-like KEM keygen.
    sk: random secret seed
    pk: derived from sk (so they are linked)
    """
    sk = random_bytes(32)
    pk = kdf(b"pk", sk, length=32)
    return pk, sk


def kem_encapsulate(pk: bytes):
    """
    Encapsulator:
      r  = random ephemeral
      mask = KDF(mask, pk)
      ct = r XOR mask
      ss_sender = KDF(ss, pk, r)
    """
    r = random_bytes(32)
    mask = kdf(b"mask", pk, length=32)
    ct = bytes(a ^ b for a, b in zip(r, mask))
    ss_sender = kdf(b"ss", pk, r, length=32)
    return ct, ss_sender


def kem_decapsulate(ct: bytes, sk: bytes, pk: bytes):
    """
    Decapsulator:
      mask = KDF(mask, pk)
      r' = ct XOR mask
      ss_receiver = KDF(ss, pk, r')
    """
    mask = kdf(b"mask", pk, length=32)
    r_prime = bytes(a ^ b for a, b in zip(ct, mask))
    ss_receiver = kdf(b"ss", pk, r_prime, length=32)
    return ss_receiver


def generate_pqc_shared_secret(key_length_bytes: int = 32):
    """
    High-level interface:
      - keygen
      - encapsulate
      - decapsulate
      - derive final K_PQC via SHA3-512
    """
    pk, sk = kem_keygen()
    ct, ss_sender = kem_encapsulate(pk)
    ss_receiver = kem_decapsulate(ct, sk, pk)

    if ss_sender != ss_receiver:
        raise ValueError("KEM failure: shared secrets do not match.")

    digest = hashlib.sha3_512(ss_sender).digest()
    K_PQC = digest[:key_length_bytes]
    return K_PQC, pk, ct
