# ==========================================================
# file_encryptor.py — AES-256-GCM encryption module
# ==========================================================
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

from utils.constants import NONCE_SIZE

# ----------------------------------------------------------
# Encrypt file bytes using AES-256-GCM
# ----------------------------------------------------------
def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    """
    Returns: ciphertext, nonce, tag
    """
    if len(key) < 32:
        raise ValueError("Hybrid key must be at least 32 bytes for AES-256-GCM.")

    aesgcm = AESGCM(key[:32])  # Use first 32 bytes
    nonce = os.urandom(NONCE_SIZE)

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Last 16 bytes are the authentication tag
    tag = ciphertext[-16:]
    ciphertext_no_tag = ciphertext[:-16]

    return ciphertext_no_tag, nonce, tag


# ----------------------------------------------------------
# Public wrapper: encrypt from file bytes
# ----------------------------------------------------------
def encrypt_file_bytes(key: bytes, file_bytes: bytes):
    return aes_gcm_encrypt(key, file_bytes)
