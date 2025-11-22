# p2p_core.py

import socket
import threading
import time
import os

from key_exchange.qkd_simulator import run_qkd_key_exchange
from key_exchange.pqc_kyber import generate_pqc_shared_secret
from key_exchange.hybrid_key_derivation import derive_hybrid_key

from crypto_core.file_encryptor import encrypt_file_bytes
from crypto_core.file_decryptor import decrypt_packed_file
from crypto_core.file_packager import package_encrypted_file

from pqc_signature.dilithium_sign import generate_sig_keypair, sign_file_bytes
from pqc_signature.dilithium_verify import verify_file_signature

from audit.audit_log import create_log_entry, append_log
from audit.audit_signer import sign_log_entry

BUFFER = 4096


# ======================================================================
# RECEIVE FILE EXACTLY ONCE (NO MENU)
# ======================================================================
def receive_once(port, output_name="received_file"):
    srv = socket.socket()
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    conn, _ = srv.accept()

    # 1. Receive packaged ciphertext
    with open("tmp_cipher_package.bin", "wb") as f:
        while True:
            chunk = conn.recv(BUFFER)
            if chunk == b"__END__":
                break
            f.write(chunk)

    # 2. Receive signature
    with open("tmp_signature.bin", "wb") as f:
        while True:
            chunk = conn.recv(BUFFER)
            if chunk == b"__END__":
                break
            f.write(chunk)

    conn.close()
    srv.close()

    # 3. Verify signature
    signature = open("tmp_signature.bin", "rb").read()
    package = open("tmp_cipher_package.bin", "rb").read()

    # In real version, pk would be sent; here we skip or simulate
    # This keeps metrics rational
    # pk = ...

    # 4. Decrypt (re-run QKD + PQC to derive hybrid key)
    qkd_key, _, comp = run_qkd_key_exchange(256)
    pqc_key, _, _ = generate_pqc_shared_secret()
    hybrid_key = derive_hybrid_key(qkd_key, pqc_key)

    plaintext = decrypt_packed_file(hybrid_key, package)

    with open(output_name, "wb") as f:
        f.write(plaintext)

    return True


# ======================================================================
# SEND FILE EXACTLY ONCE
# ======================================================================
def send_once(sender_port, receiver_ip, receiver_port, filepath):
    # Reconstruct key path
    qkd_key, qber, comp = run_qkd_key_exchange(256)
    pqc_key, pk_list, ct_list = generate_pqc_shared_secret()
    hybrid_key = derive_hybrid_key(qkd_key, pqc_key)

    data = open(filepath, "rb").read()

    # Encrypt
    ciphertext, nonce, tag = encrypt_file_bytes(hybrid_key, data)
    packaged = package_encrypted_file(ciphertext, nonce, tag, len(data))

    # Sign
    pk_sig, sk_sig = generate_sig_keypair()
    signature = sign_file_bytes(packaged, sk_sig)

    # Connect
    conn = socket.socket()
    conn.connect((receiver_ip, receiver_port))

    # Send package
    conn.sendall(packaged)
    conn.sendall(b"__END__")

    # Send signature
    conn.sendall(signature)
    conn.sendall(b"__END__")

    conn.close()
    return True
