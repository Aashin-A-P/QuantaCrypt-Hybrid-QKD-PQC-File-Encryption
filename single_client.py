import socket
import os
import struct
import argparse

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
            raise ConnectionError("Lost connection while receiving")
        data += packet
    return data

def main():
    print("\n=== Quantum-Safe Secure File Transfer Client ===")
    print(f"Connecting to server {HOST}:{PORT}...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    print("[CLIENT] Receiving hybrid key...")
    hybrid_key = recv_bytes(s)
    print(f"[CLIENT] Hybrid key length: {len(hybrid_key)} bytes")

    while True:
        print("\n===== CLIENT MENU =====")
        print("1. Receive file from server")
        print("2. Send file to server")
        print("3. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            print("[CLIENT] Waiting for encrypted file...")
            enc_data = recv_bytes(s)

            temp = "client_received.bin"
            with open(temp, "wb") as f:
                f.write(enc_data)

            out_path = input("Save decrypted file as: ").strip()
            decrypt_file(temp, out_path, hybrid_key)
            print("[CLIENT] File decrypted successfully.")

        elif choice == "2":
            file_path = input("Enter file path to send: ").strip()
            if not os.path.exists(file_path):
                print("File not found.")
                continue

            enc_path = "client_encrypted.bin"
            encrypt_file(file_path, enc_path, hybrid_key)

            print("[CLIENT] Sending encrypted file...")
            data = open(enc_path, "rb").read()
            send_bytes(s, data)
            print("[CLIENT] File sent.")

        elif choice == "3":
            print("Client closing...")
            break

        else:
            print("Invalid choice.")

    s.close()


if __name__ == "__main__":
    main()
