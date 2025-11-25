import socket
import json
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.io_utils import read_file_bytes, write_file_bytes
from key_exchange.qkd_simulator import run_qkd_key_exchange
from key_exchange.pqc_kyber import generate_pqc_shared_secret
from key_exchange.hybrid_key_derivation import derive_hybrid_key

from crypto_core.file_encryptor import encrypt_file_bytes
from crypto_core.file_packager import package_encrypted_file

from pqc_signature.dilithium_sign import generate_sig_keypair, sign_file_bytes

from audit.audit_log import create_log_entry, append_log
from audit.audit_signer import sign_log_entry
from audit.pychain_anchor import anchor_to_blockchain

HOST = "0.0.0.0"
PORT = 7000

def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())

def send_file(conn, filepath):
    size = os.path.getsize(filepath)
    send_json(conn, {
        "type": "FILE_PART",
        "filename": os.path.basename(filepath),
        "size": size
    })

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            conn.sendall(chunk)

def start_server():
    print("=====================================================")
    print("         QuantaCrypt SECURE SERVER (SENDER)")
    print("=====================================================")

    srv = socket.socket()
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[SERVER] Waiting for client on {HOST}:{PORT} ...")

    conn, addr = srv.accept()
    print(f"[SERVER] Connected to client {addr}\n")

    while True:
        filepath = input("Enter file path to SEND (or X to exit): ").strip()

        if filepath.lower() == "x":
            print("[SERVER] Exiting.")
            conn.close()
            return

        if not os.path.exists(filepath):
            print("[ERROR] File not found.")
            continue

        filename = os.path.basename(filepath)
        plaintext = read_file_bytes(filepath)
        fsize = len(plaintext)

        print("\n========== QUANTACRYPT ENCRYPTION ==========")

        # ----- QKD -----
        qkd_key, qber, compromised = run_qkd_key_exchange(eve=False)
        print(f"[QKD] QBER={qber:.4f}, compromised={compromised}")
        if compromised:
            print("[ABORT] Quantum channel compromised.")
            continue

        # ----- KYBER -----
        pqc_key, pk_list, ct_list = generate_pqc_shared_secret()

        # ----- HYBRID -----
        hybrid_key = derive_hybrid_key(qkd_key, pqc_key)

        # ----- AES ENCRYPT -----
        ciphertext, nonce, tag = encrypt_file_bytes(hybrid_key, plaintext)
        packaged = package_encrypted_file(ciphertext, nonce, tag, fsize)

        write_file_bytes("cipher_package.bin", packaged)

        # ----- SIGNATURE -----
        pk_sig, sk_sig = generate_sig_keypair()
        signature = sign_file_bytes(packaged, sk_sig)

        write_file_bytes("cipher_signature.bin", signature)
        write_file_bytes("sender_pk_sig.bin", pk_sig)
        write_file_bytes("sender_sk_sig.bin", sk_sig)
        write_file_bytes("sender_hybrid_key.bin", hybrid_key)

        # ----- AUDIT + BLOCKCHAIN -----
        entry = create_log_entry("SERVER_SENT", {
            "filename": filename,
            "bytes": fsize
        })
        append_log(sign_log_entry(entry, sk_sig, pk_sig))
        anchor_to_blockchain()

        send_json(conn, {
            "type": "INCOMING_FILE",
            "filename": filename
        })

        send_file(conn, "cipher_package.bin")
        send_file(conn, "cipher_signature.bin")
        send_file(conn, "sender_pk_sig.bin")
        send_file(conn, "sender_sk_sig.bin")
        send_file(conn, "sender_hybrid_key.bin")

        print("\n[SUCCESS] Secure file transfer completed.\n")


if __name__ == "__main__":
    start_server()
