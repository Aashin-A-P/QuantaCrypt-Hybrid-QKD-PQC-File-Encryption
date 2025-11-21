import socket
import threading
import struct
import os

from qkd.qkd_simulator import generate_qkd_key
from pqc.kyber_simulator import generate_pqc_shared_secret
from hybrid_key.key_fusion import derive_hybrid_key
from crypto_core.file_crypto import encrypt_file, decrypt_file


HOST = "0.0.0.0"
PORT = 9090

clients = {} 

def send_msg(conn, opcode: int, payload: bytes = b""):
    conn.sendall(bytes([opcode]))
    conn.sendall(struct.pack(">Q", len(payload)))
    if payload:
        conn.sendall(payload)


def recv_msg(conn):
    opcode = conn.recv(1)
    if not opcode:
        return None, None
    opcode = opcode[0]

    size_data = conn.recv(8)
    if not size_data:
        return None, None

    size = struct.unpack(">Q", size_data)[0]

    payload = b""
    while len(payload) < size:
        packet = conn.recv(size - len(payload))
        if not packet:
            return None, None
        payload += packet

    return opcode, payload


# Handle Single Client
def handle_client(client_id, conn, addr):
    print(f"\n[SERVER] Client {client_id} connected from {addr}")

    k_qkd, _ = generate_qkd_key()
    k_pqc, _, _ = generate_pqc_shared_secret()

    hybrid_key = derive_hybrid_key(k_qkd, k_pqc, length_bytes=64)
    clients[client_id] = (conn, addr, hybrid_key)

    print(f"[SERVER] Hybrid key for {client_id}: {len(hybrid_key)} bytes")

    send_msg(conn, 0x01, hybrid_key)

    while True:
        try:
            opcode, payload = recv_msg(conn)
            if opcode is None:
                break

            if opcode == 0x10:
                name_len = struct.unpack(">Q", payload[:8])[0]
                file_name = payload[8:8+name_len].decode()
                encrypted_bytes = payload[8+name_len:]

                print(f"[SERVER] Receiving '{file_name}' from {client_id}")

                temp = f"{client_id}_recv_enc.bin"
                with open(temp, "wb") as f:
                    f.write(encrypted_bytes)

                save_as = f"{client_id}_{file_name}"
                decrypt_file(temp, save_as, hybrid_key)

                print(f"[SERVER] Saved decrypted file: {save_as}")

            elif opcode == 0x20:
                req_file = payload.decode()
                print(f"[SERVER] {client_id} requested: {req_file}")

                if not os.path.exists(req_file):
                    send_msg(conn, 0x40, b"ERROR: File not found")
                    continue

                # Encrypt file to send
                enc_tmp = f"{client_id}_server_enc.bin"
                encrypt_file(req_file, enc_tmp, hybrid_key)
                encrypted = open(enc_tmp, "rb").read()

                # Build filename header
                file_name = os.path.basename(req_file).encode()
                out_payload = (
                    struct.pack(">Q", len(file_name)) +
                    file_name +
                    encrypted
                )

                send_msg(conn, 0x30, out_payload)
                print(f"[SERVER] Sent encrypted '{req_file}' to {client_id}")

        except Exception as e:
            print(f"[SERVER] Error with {client_id}: {e}")
            break

    print(f"[SERVER] Client {client_id} disconnected")
    conn.close()
    del clients[client_id]

def admin_menu():
    while True:
        print("\n====== SERVER MENU ======")
        print("1. List connected clients")
        print("2. Push file to a client")
        print("3. Exit")
        print("==========================")
        choice = input("Enter choice: ")

        if choice == "1":
            print("\nConnected Clients:")
            for cid, (_, addr, _) in clients.items():
                print(f" - {cid} at {addr}")

        elif choice == "2":
            cid = input("Enter client ID: ").strip()
            if cid not in clients:
                print("Invalid client ID")
                continue

            file_path = input("File path to send: ").strip()
            if not os.path.exists(file_path):
                print("File not found")
                continue

            conn, _, hybrid_key = clients[cid]

            enc_tmp = f"{cid}_server_push.bin"
            encrypt_file(file_path, enc_tmp, hybrid_key)
            encrypted = open(enc_tmp, "rb").read()

            file_name = os.path.basename(file_path).encode()
            payload = (
                struct.pack(">Q", len(file_name)) +
                file_name +
                encrypted
            )

            send_msg(conn, 0x30, payload)
            print(f"[SERVER] Sent file '{file_path}' to {cid}")

        elif choice == "3":
            print("[SERVER] Shutting down...")
            os._exit(0)

def main():
    print("=== Quantum-Safe Multi-Client Secure File Transfer Server ===")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(10)

    print(f"[SERVER] Listening on {HOST}:{PORT}\n")

    threading.Thread(target=admin_menu, daemon=True).start()

    client_counter = 1
    while True:
        conn, addr = s.accept()
        cid = f"client_{client_counter}"
        client_counter += 1

        threading.Thread(
            target=handle_client, args=(cid, conn, addr), daemon=True
        ).start()


if __name__ == "__main__":
    main()
