# ==========================================================
# file_packager.py — Constructs file header + packaging
# ==========================================================

from utils.constants import (
    MAGIC_BYTES,
    VERSION,
    NONCE_SIZE,
    TAG_SIZE,
)
from utils.io_utils import pack_uint64, unpack_uint64


# ----------------------------------------------------------
# Pack encrypted file with metadata header
# ----------------------------------------------------------
def package_encrypted_file(ciphertext: bytes, nonce: bytes, tag: bytes, original_file_size: int):
    """
    Returns a fully packaged encrypted file ready to be signed.
    """

    header = bytearray()
    header += MAGIC_BYTES               # 6 bytes
    header += VERSION.to_bytes(1, "big")  # 1 byte
    header += nonce                     # 12 bytes
    header += tag                       # 16 bytes
    header += pack_uint64(original_file_size)  # 8 bytes

    return bytes(header) + ciphertext


# ----------------------------------------------------------
# Unpack header + encrypted content
# ----------------------------------------------------------
def unpack_encrypted_file(packed_data: bytes):
    """
    Extracts metadata + ciphertext.
    Returns (nonce, tag, file_size, ciphertext)
    """
    offset = 0

    # MAGIC
    magic = packed_data[:len(MAGIC_BYTES)]
    if magic != MAGIC_BYTES:
        raise ValueError("Invalid file format. Magic bytes mismatch.")
    offset += len(MAGIC_BYTES)

    # VERSION
    version = packed_data[offset]
    offset += 1

    # NONCE
    nonce = packed_data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    # TAG
    tag = packed_data[offset:offset + TAG_SIZE]
    offset += TAG_SIZE

    # FILE SIZE (uint64)
    file_size = unpack_uint64(packed_data[offset:offset + 8])
    offset += 8

    # CIPHERTEXT
    ciphertext = packed_data[offset:]

    return version, nonce, tag, file_size, ciphertext
