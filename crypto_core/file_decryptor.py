# AES-256-GCM decryption module

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.constants import NONCE_SIZE
from utils.io_utils import ensure_file_exists
from .file_packager import unpack_encrypted_file

def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes):
    aesgcm = AESGCM(key[:32])

    # AESGCM expects ciphertext + tag concatenated
    ct_with_tag = ciphertext + tag

    plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
    return plaintext

def decrypt_packed_file(key: bytes, packed_bytes: bytes):
    version, nonce, tag, file_size, ciphertext = unpack_encrypted_file(packed_bytes)

    plaintext = aes_gcm_decrypt(key, ciphertext, nonce, tag)

    return plaintext[:file_size]
