# ==========================================================
# io_utils.py  —  File reading/writing and safe I/O wrappers
# ==========================================================

import os

# ----------------------------------------------------------
# Read file bytes safely
# ----------------------------------------------------------
def read_file_bytes(path: str) -> bytes:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        return f.read()

# ----------------------------------------------------------
# Write bytes to a file safely
# ----------------------------------------------------------
def write_file_bytes(path: str, data: bytes):
    # Ensure parent directory exists
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "wb") as f:
        f.write(data)

# ----------------------------------------------------------
# Check if file is a QuantaCrypt encrypted file
# ----------------------------------------------------------
def is_project_file(data: bytes, magic: bytes) -> bool:
    return data.startswith(magic)

# ----------------------------------------------------------
# Convert file size to 8-byte big endian
# ----------------------------------------------------------
def pack_uint64(value: int) -> bytes:
    return value.to_bytes(8, byteorder="big")

# ----------------------------------------------------------
# Read 8-byte big endian int
# ----------------------------------------------------------
def unpack_uint64(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")

# ----------------------------------------------------------
# Validate file input path
# ----------------------------------------------------------
def ensure_file_exists(path: str):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File does not exist: {path}")
