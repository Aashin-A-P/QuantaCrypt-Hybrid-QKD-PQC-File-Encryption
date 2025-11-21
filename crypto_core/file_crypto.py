import os
import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

#  KEY DERIVATION FROM HYBRID KEY (64 bytes)

def derive_symmetric_keys(hybrid_key: bytes):
    """
    Split the 64-byte hybrid key into:
    - 32 bytes AES-256 key
    - 32 bytes metadata/HMAC/additional key (future use)
    """
    if len(hybrid_key) < 64:
        raise ValueError("Hybrid key must be at least 64 bytes")

    enc_key = hybrid_key[:32]      # AES-256 key
    meta_key = hybrid_key[32:64]   # Can be used for additional auth

    return enc_key, meta_key

#  AES-GCM FILE ENCRYPTION

def encrypt_file(input_path: str, output_path: str, hybrid_key: bytes):
    """
    Encrypt a file using AES-256-GCM.
    File structure:
        [16-byte nonce]
        [4-byte tag length]
        [ciphertext || tag]
    """
    # Derive AES key
    enc_key, _ = derive_symmetric_keys(hybrid_key)
    aesgcm = AESGCM(enc_key)

    # Generate nonce (12 bytes recommended for AES-GCM)
    nonce = os.urandom(12)

    # Read plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    start = time.time()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    end = time.time()

    # Write encrypted file (nonce + ciphertext)
    with open(output_path, "wb") as f:
        f.write(nonce)
        # store ciphertext length for debugging/metadata
        f.write(struct.pack(">I", len(ciphertext)))
        f.write(ciphertext)

    return {
        "input_size": len(plaintext),
        "output_size": len(ciphertext) + 16,
        "nonce": nonce.hex(),
        "encryption_time_ms": (end - start) * 1000,
    }

#  AES-GCM FILE DECRYPTION

def decrypt_file(input_path: str, output_path: str, hybrid_key: bytes):
    """
    Decrypt a file produced by encrypt_file().
    """
    enc_key, _ = derive_symmetric_keys(hybrid_key)
    aesgcm = AESGCM(enc_key)

    with open(input_path, "rb") as f:
        nonce = f.read(12)
        ct_len = struct.unpack(">I", f.read(4))[0]
        ciphertext = f.read(ct_len)

    start = time.time()
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    end = time.time()

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return {
        "plaintext_size": len(plaintext),
        "nonce": nonce.hex(),
        "decryption_time_ms": (end - start) * 1000,
    }
