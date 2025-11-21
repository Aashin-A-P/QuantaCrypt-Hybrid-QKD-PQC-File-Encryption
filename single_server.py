import socket
import os
import struct
import argparse

from qkd.qkd_simulator import generate_qkd_key
from pqc.kyber_simulator import generate_pqc_shared_secret
from hybrid_key.key_fusion import derive_hybrid_key
from crypto_core.file_crypto import encrypt_file, decrypt_file

HOST = "127.0.0.1"
PORT = 9090

def send_bytes(conn, data: bytes):
    conn.sendall(struct.pack(">Q", len(data)))
    conn.sendall(data)

def recv_bytes(conn):
    size = struct.unpack(">Q", conn.recv(8))[0]
    data = b""
    while len(data) < size:
        packet = conn.recv(size - len(data))
        if not packet:
            raise ConnectionError("Connection lost while receiving data")
        data += packet
    return data

def main():
    print("\n=== Quantum-Safe Secure File Transfer Server ===")

    print("\n[1] Generating QKD key...")
    k_qkd, qber = generate_qkd_key()

    print("[2] Generating PQC key...")
    k_pqc, _, _ = generate_pqc_shared_secret()

    print("[3] Deriving Hybrid Key...")
    hybrid_key = derive_hybrid_key(k_qkd, k_pqc, length_bytes=64)

    print(f"Hybrid key generated: {len(hybrid_key)} bytes\n")

    print(f"Listening on {HOST}:{PORT} ...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)

    conn, addr = s.accept()
    print(f"Client connected from {addr}")

    print("[SERVER] Sending session hybrid key to client...")
    send_bytes(conn, hybrid_key)

    while True:
        print("\n===== SERVER MENU =====")
        print("1. Send file to client")
        print("2. Receive file from client")
        print("3. Exit")
        
        choice = input("Select option: ").strip()

        if choice == "1":
            file_path = input("Enter path to file: ").strip()
            if not os.path.exists(file_path):
                print("File not found.")
                continue

            enc_path = "server_encrypted.bin"
            res = encrypt_file(file_path, enc_path, hybrid_key)
            print(f"[SERVER] File encrypted → {enc_path}")

            print("[SERVER] Sending encrypted file to client...")
            data = open(enc_path, "rb").read()
            send_bytes(conn, data)
            print("[SERVER] File sent.")

        elif choice == "2":
            print("[SERVER] Waiting to receive encrypted file...")
            encrypted_data = recv_bytes(conn)

            temp_path = "server_received.bin"
            with open(temp_path, "wb") as f:
                f.write(encrypted_data)

            out_path = input("Enter output path to save decrypted file: ").strip()
            decrypt_file(temp_path, out_path, hybrid_key)
            print(f"[SERVER] File saved as: {out_path}")

        elif choice == "3":
            print("Exiting server...")
            break

        else:
            print("Invalid choice. Try again.")

    conn.close()
    s.close()


if __name__ == "__main__":
    main()
