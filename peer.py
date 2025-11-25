# peer.py
import socket
import json
import os
import sys
import threading

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# === IMPORT EXISTING QUANTACRYPT MODULES ===
from utils.io_utils import read_file_bytes, write_file_bytes
from key_exchange.qkd_simulator import run_qkd_key_exchange
from key_exchange.pqc_kyber import generate_pqc_shared_secret
from key_exchange.hybrid_key_derivation import derive_hybrid_key
from crypto_core.file_encryptor import encrypt_file_bytes
from crypto_core.file_packager import package_encrypted_file
from crypto_core.file_decryptor import decrypt_packed_file
from pqc_signature.dilithium_sign import generate_sig_keypair, sign_file_bytes
from pqc_signature.dilithium_verify import verify_file_signature
from audit.audit_log import create_log_entry, append_log
from audit.audit_signer import sign_log_entry
from audit.pychain_anchor import anchor_to_blockchain

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7000
print(f"[P2P] Running on port {PORT}")

def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def recv_json(conn):
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(1)
        if not chunk:
            break
        buf += chunk
    return json.loads(buf.decode().strip())

def send_file(conn, filepath):
    size = os.path.getsize(filepath)
    send_json(conn, {
        "type": "FILE_PART",
        "filename": os.path.basename(filepath),
        "size": size
    })

    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            conn.sendall(chunk)


def recv_file(conn):
    header = recv_json(conn)
    filename = header["filename"]
    size = header["size"]

    print(f"[P2P] Receiving {filename} ({size} bytes)")

    data = bytearray()
    remaining = size

    while remaining > 0:
        chunk = conn.recv(min(4096, remaining))
        if not chunk:
            break
        data.extend(chunk)
        remaining -= len(chunk)

    return filename, bytes(data)

def listener():
    srv = socket.socket()
    srv.bind(("0.0.0.0", PORT))
    srv.listen(5)
    print(f"[P2P] Listening on {PORT}...")

    while True:
        conn, addr = srv.accept()
        print(f"[P2P] Incoming connection from {addr}")
        threading.Thread(target=receive_secure_file, args=(conn,)).start()


def receive_secure_file(conn):
    hdr = recv_json(conn)

    if hdr["type"] != "INCOMING_FILE":
        print("[P2P] Invalid header:", hdr)
        return

    filename = hdr["filename"]
    print(f"[P2P] Incoming secure file: {filename}")

    # === Receive all artifacts (same as client.py) ===
    _, package = recv_file(conn)
    _, signature = recv_file(conn)
    _, pk_sig = recv_file(conn)
    _, sk_sig = recv_file(conn)
    _, hybrid_key = recv_file(conn)

    # Save raw artifacts
    write_file_bytes("cipher_package.bin", package)
    write_file_bytes("cipher_signature.bin", signature)
    write_file_bytes("sender_pk_sig.bin", pk_sig)
    write_file_bytes("sender_sk_sig.bin", sk_sig)
    write_file_bytes("sender_hybrid_key.bin", hybrid_key)

    print("\n========== DECRYPTION ==========")

    # QKD
    qkd_key, qber, compromised = run_qkd_key_exchange()
    print(f"[QKD] QBER={qber}, compromised={compromised}")
    if compromised:
        print("[P2P] Rejecting file due to QKD attack.")
        return

    # PQC (to match your client mechanism)
    pqc_key, _, _ = generate_pqc_shared_secret()
    _ = derive_hybrid_key(qkd_key, pqc_key)

    # Verify signature
    valid = verify_file_signature(package, signature, pk_sig)
    print(f"[P2P] Signature valid: {valid}")
    if not valid:
        print("[P2P] Invalid signature. ABORT.")
        return

    # Decrypt using Hybrid key
    out = decrypt_packed_file(hybrid_key, package)
    out_path = "decrypted_" + filename
    write_file_bytes(out_path, out)

    print(f"[P2P] File decrypted → {out_path}")

    # Audit
    entry = create_log_entry("P2P_RECEIVED", {"filename": filename})
    append_log(sign_log_entry(entry, sk_sig, pk_sig))

    conn.close()

def send_secure(peer_ip, peer_port, filepath):
    conn = socket.socket()
    conn.connect((peer_ip, peer_port))
    print(f"[P2P] Connected to {peer_ip}:{peer_port}")

    filename = os.path.basename(filepath)
    plaintext = read_file_bytes(filepath)

    # === QKD ===
    qkd_key, qber, compromised = run_qkd_key_exchange()
    print(f"[QKD] QBER={qber}, compromised={compromised}")
    if compromised:
        print("[ABORT] QKD compromised.")
        return

    # === Kyber ===
    pqc_key, pk_list, ct_list = generate_pqc_shared_secret()

    # === Hybrid ===
    hybrid_key = derive_hybrid_key(qkd_key, pqc_key)

    # === Encrypt ===
    ciphertext, nonce, tag = encrypt_file_bytes(hybrid_key, plaintext)
    packaged = package_encrypted_file(ciphertext, nonce, tag, len(plaintext))
    write_file_bytes("cipher_package.bin", packaged)

    # === Signature ===
    pk_sig, sk_sig = generate_sig_keypair()
    signature = sign_file_bytes(packaged, sk_sig)

    write_file_bytes("cipher_signature.bin", signature)
    write_file_bytes("sender_pk_sig.bin", pk_sig)
    write_file_bytes("sender_sk_sig.bin", sk_sig)
    write_file_bytes("sender_hybrid_key.bin", hybrid_key)

    # === Audit ===
    entry = create_log_entry("P2P_SENT", {"filename": filename})
    append_log(sign_log_entry(entry, sk_sig, pk_sig))
    anchor_to_blockchain()

    # === Send header ===
    send_json(conn, {"type": "INCOMING_FILE", "filename": filename})

    # === Send artifacts ===
    send_file(conn, "cipher_package.bin")
    send_file(conn, "cipher_signature.bin")
    send_file(conn, "sender_pk_sig.bin")
    send_file(conn, "sender_sk_sig.bin")
    send_file(conn, "sender_hybrid_key.bin")

    print("[P2P] File sent successfully.")
    conn.close()

if __name__ == "__main__":
    threading.Thread(target=listener, daemon=True).start()

    while True:
        print("\n1) Send File")
        print("2) Exit")
        choice = input("> ").strip()

        if choice == "1":
            raw = input("Peer IP: ").strip()   # supports "127.0.0.1:7001"
            filepath = input("File Path: ").strip()

            if ":" in raw:
                peer_ip, peer_port = raw.split(":")
                peer_port = int(peer_port)
            else:
                peer_ip = raw
                peer_port = PORT

            send_secure(peer_ip, peer_port, filepath)

        else:
            break
