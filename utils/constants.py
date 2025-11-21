# ==========================================================
# constants.py  —  Common constants shared across modules
# ==========================================================

# Magic bytes that identify project-specific encrypted files
MAGIC_BYTES = b"QCFILE"

# File format version
VERSION = 1

# AES-GCM parameters
NONCE_SIZE = 12      # 96-bit recommended
TAG_SIZE = 16        # 128-bit authentication tag

# PQC signature sizes vary by algorithm (example: Dilithium2)
MAX_SIGNATURE_SIZE = 2700

# Header size (excluding signature)
HEADER_FIXED_SIZE = (
    len(MAGIC_BYTES) + 
    1 +                 # version
    NONCE_SIZE + 
    TAG_SIZE +
    8                   # file_size (uint64)
)

# Audit log file name
AUDIT_LOG_FILE = "audit.log"

# Utility
ENCODING = "utf-8"
