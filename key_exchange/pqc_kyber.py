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


def clamp_to_byte_list(b: bytes) -> list:
    """Convert ANY bytes object into a list of 0–255 integers."""
    return [x for x in b]    # each x is already 0..255

def kyber_generate_keypair():
    """
    sk = random 32 bytes
    pk = KDF(sk)
    ALWAYS returned as byte lists IN 0..255 RANGE
    """
    sk = random_bytes(32)
    pk_bytes = kdf(b"pk", sk, length=32)
    pk_list = clamp_to_byte_list(pk_bytes)
    return pk_list, sk


def kyber_encapsulate(pk_list: list):
    """
    r = random
    ct = r XOR mask
    ss = KDF(pk || r)
    ALL VALUES FOR ct ARE IN 0..255 RANGE
    """

    pk = bytes(pk_list)
    r = random_bytes(32)

    mask = kdf(b"mask", pk, length=32)
    mask_list = clamp_to_byte_list(mask)

    ct_list = [(a ^ b) for a, b in zip(r, mask_list)]

    ss_bytes = kdf(b"ss", pk, r, length=32)
    return ct_list, ss_bytes


def kyber_decapsulate(ct_list: list, sk: bytes, pk_list: list):
    pk = bytes(pk_list)

    mask = kdf(b"mask", pk, length=32)
    mask_list = clamp_to_byte_list(mask)

    r_prime = bytes([(c ^ m) for c, m in zip(ct_list, mask_list)])
    ss_recv = kdf(b"ss", pk, r_prime, length=32)
    return ss_recv


def generate_pqc_shared_secret(key_length_bytes: int = 32):
    """
    Returns:
        K_PQC (bytes)
        pk_list (0..255)
        ct_list (0..255)
    """

    pk_list, sk = kyber_generate_keypair()
    ct_list, ss_sender = kyber_encapsulate(pk_list)
    ss_receiver = kyber_decapsulate(ct_list, sk, pk_list)

    if ss_sender != ss_receiver:
        raise ValueError("KEM mismatch — simulated failure.")

    digest = hashlib.sha3_512(ss_sender).digest()
    final_key = digest[:key_length_bytes]

    return final_key, pk_list, ct_list
