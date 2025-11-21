import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os

# Read file bytes safely
def read_file_bytes(path: str) -> bytes:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        return f.read()

# Write bytes to a file safely
def write_file_bytes(path: str, data: bytes):
    # If writing to current folder, dirname = "" -> skip folder creation
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)

    with open(path, "wb") as f:
        f.write(data)

def is_project_file(data: bytes, magic: bytes) -> bool:
    return data.startswith(magic)

def pack_uint64(value: int) -> bytes:
    return value.to_bytes(8, byteorder="big")

def unpack_uint64(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")

def ensure_file_exists(path: str):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File does not exist: {path}")
