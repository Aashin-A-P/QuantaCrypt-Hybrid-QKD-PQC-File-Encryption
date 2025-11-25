import socket
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.io_utils import write_file_bytes, read_file_bytes
from crypto_core.file_decryptor import decrypt_packed_file
from key_exchange.qkd_simulator import run_qkd_key_exchange
from key_exchange.pqc_kyber import generate_pqc_shared_secret
from key_exchange.hybrid_key_derivation import derive_hybrid_key
from pqc_signature.dilithium_verify import verify_file_signature
from audit.audit_log import create_log_entry, append_log
from audit.audit_signer import sign_log_entry

HOST = "127.0.0.1"
PORT = 7000

def recv_json(conn):
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(1)
        if not chunk:
            continue
        buf += chunk
    return json.loads(buf.decode().strip())

def recv_file(conn):
    header = recv_json(conn)

    if header["type"] != "FILE_PART":
        print("[CLIENT] ERROR: Invalid file-part header:", header)
        return None, None

    filename = header["filename"]
    size = header["size"]

    print(f"[CLIENT] Receiving {filename} ({size} bytes)")

    data = bytearray()
    remaining = size

    while remaining > 0:
        chunk = conn.recv(min(4096, remaining))
        if not chunk:
            print("[CLIENT ERROR] Connection closed early!")
            break
        data.extend(chunk)
        remaining -= len(chunk)

    return filename, bytes(data)

def start_client():
    print("=====================================================")
    print("            QUANTACRYPT SECURE CLIENT")
    print("=====================================================")

    conn = socket.socket()
    conn.connect((HOST, PORT))
    print("[CLIENT] Connected to server.\n")

    while True:
        print("\nOptions:")
        print("1) Receive Secure File")
        print("2) Exit")
        choice = input("Choice: ")

        if choice == "2":
            conn.close()
            return

        if choice != "1":
            continue

        print("[CLIENT] Waiting for secure file...")

        hdr = recv_json(conn)
        if hdr["type"] != "INCOMING_FILE":
            print("[CLIENT] Unexpected header:", hdr)
            continue

        filename = hdr["filename"]
        print(f"[CLIENT] Incoming secure file: {filename}")

        # Receive 5 artifacts
        fname1, package = recv_file(conn)
        fname2, signature = recv_file(conn)
        fname3, pk_sig = recv_file(conn)
        fname4, sk_sig = recv_file(conn)
        fname5, hybrid_key = recv_file(conn)

        # Save
        write_file_bytes("cipher_package.bin", package)
        write_file_bytes("cipher_signature.bin", signature)
        write_file_bytes("sender_pk_sig.bin", pk_sig)
        write_file_bytes("sender_sk_sig.bin", sk_sig)
        write_file_bytes("sender_hybrid_key.bin", hybrid_key)

        print("\n========== QUANTACRYPT DECRYPTION ==========")

        # QKD
        qkd_key, qber, compromised = run_qkd_key_exchange(eve=False)
        print(f"[QKD] QBER={qber}, compromised={compromised}")
        if compromised:
            print("[CLIENT] Channel compromised. Rejecting.")
            continue

        # PQC Kyber (not used for decrypt, only to prove pipeline)
        pqc_key, _, _ = generate_pqc_shared_secret()

        # Hybrid (not used)
        _ = derive_hybrid_key(qkd_key, pqc_key)

        # Signature Verify
        valid = verify_file_signature(package, signature, pk_sig)
        print(f"[CLIENT] Signature valid: {valid}")
        if not valid:
            print("[CLIENT] Invalid signature. ABORT.")
            continue

        # Decrypt
        outdata = decrypt_packed_file(hybrid_key, package)

        out_path = "decrypted_" + filename
        write_file_bytes(out_path, outdata)
        print(f"[CLIENT] Decrypted → {out_path}")

        # Audit
        entry = create_log_entry("CLIENT_RECEIVED", {"file": filename})
        append_log(sign_log_entry(entry, sk_sig, pk_sig))


if __name__ == "__main__":
    start_client()
