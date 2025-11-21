import socket
import struct
import os

from crypto_core.file_crypto import encrypt_file, decrypt_file


HOST = "127.0.0.1"
PORT = 9090


# ======================================================
# Utility Protocol
# ======================================================

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

    size = struct.unpack(">Q", conn.recv(8))[0]

    payload = b""
    while len(payload) < size:
        packet = conn.recv(size - len(payload))
        if not packet:
            return None, None
        payload += packet

    return opcode, payload


# ======================================================
# Main Client
# ======================================================

def main():
    print("\n=== Quantum-Safe Secure File Transfer Client ===")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    print("[CLIENT] Connected to server.")

    # Receive hybrid session key
    opcode, hybrid_key = recv_msg(s)
    print(f"[CLIENT] Session key received ({len(hybrid_key)} bytes)")

    while True:
        print("\n====== CLIENT MENU ======")
        print("1. Pull file from server")
        print("2. Send file to server")
        print("3. Exit")
        print("==========================")
        choice = input("Select: ").strip()

        # ============================================
        # 1. Pull File from Server
        # ============================================
        if choice == "1":
            file_req = input("Enter server file path: ").strip()
            send_msg(s, 0x20, file_req.encode())

            opcode, payload = recv_msg(s)
            if opcode == 0x40:
                print(payload.decode())
                continue

            # Parse filename
            name_len = struct.unpack(">Q", payload[:8])[0]
            file_name = payload[8:8+name_len].decode()
            encrypted_bytes = payload[8+name_len:]

            temp = "client_recv_temp.bin"
            with open(temp, "wb") as f:
                f.write(encrypted_bytes)

            decrypt_file(temp, file_name, hybrid_key)
            print(f"[CLIENT] File saved as '{file_name}'")

        # ============================================
        # 2. Send File to Server
        # ============================================
        elif choice == "2":
            path = input("Enter local file path: ").strip()
            if not os.path.exists(path):
                print("File does not exist.")
                continue

            enc_tmp = "client_send_temp.bin"
            encrypt_file(path, enc_tmp, hybrid_key)
            encrypted = open(enc_tmp, "rb").read()

            file_name = os.path.basename(path).encode()
            payload = (
                struct.pack(">Q", len(file_name)) +
                file_name +
                encrypted
            )

            send_msg(s, 0x10, payload)
            print("[CLIENT] File sent to server.")

        # ============================================
        # 3. Exit
        # ============================================
        elif choice == "3":
            print("[CLIENT] Exiting.")
            break

    s.close()


if __name__ == "__main__":
    main()
