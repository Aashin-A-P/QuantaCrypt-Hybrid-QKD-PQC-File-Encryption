import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.io_utils import read_file_bytes, write_file_bytes
from utils.hashing import sha3_512

# KEY EXCHANGE
from key_exchange.qkd_simulator import run_qkd_key_exchange
from key_exchange.pqc_kyber import generate_pqc_shared_secret
from key_exchange.hybrid_key_derivation import derive_hybrid_key

# CRYPTO CORE
from crypto_core.file_encryptor import encrypt_file_bytes
from crypto_core.file_packager import package_encrypted_file
from crypto_core.file_decryptor import decrypt_packed_file

# SIGNATURES
from pqc_signature.dilithium_sign import generate_sig_keypair, sign_file_bytes
from pqc_signature.dilithium_verify import verify_file_signature

# AUDIT LOG
from audit.audit_log import create_log_entry, append_log
from audit.audit_signer import sign_log_entry, verify_log_entry


# SENDER WORKFLOW

def sender_encrypt_and_sign(input_file: str):
    print("\n=== SENDER SIDE ===")

    # Load file
    plaintext = read_file_bytes(input_file)
    file_size = len(plaintext)
    print(f"[+] Loaded file: {input_file} ({file_size} bytes)")

    # QKD KEY
    qkd_key = run_qkd_key_exchange()
    print("[+] QKD Key Generated")

    # PQC KEM 
    pqc_key, pk_kem, ct_kem = generate_pqc_shared_secret()
    print("[+] PQC Shared Secret Generated")

    # HYBRID KEY
    hybrid_key = derive_hybrid_key(qkd_key, pqc_key)
    print("[+] Hybrid Key Derived (QKD + PQC)")

    # ENCRYPTION
    ciphertext, nonce, tag = encrypt_file_bytes(hybrid_key, plaintext)
    packaged = package_encrypted_file(ciphertext, nonce, tag, file_size)
    print("[+] File Encrypted & Packaged")

    # SIGNING
    pk_sig, sk_sig = generate_sig_keypair()
    signature = sign_file_bytes(packaged, sk_sig)
    print("[+] PQC Signature Created")

    # AUDIT LOG
    entry = create_log_entry(
        "FILE_ENCRYPTED",
        {"filename": input_file, "bytes": file_size}
    )
    signed_entry = sign_log_entry(entry, sk_sig, pk_sig)
    append_log(signed_entry)
    print("[+] Audit Log Entry Added")

    # Return everything receiver needs
    return packaged, signature, pk_sig, hybrid_key


# RECEIVER WORKFLOW
def receiver_verify_and_decrypt(packed_bytes: bytes, signature: bytes, pk_sig: bytes, hybrid_key: bytes, output_file: str):
    print("\n=== RECEIVER SIDE ===")

    # SIGNATURE VERIFICATION
    print("[*] Verifying PQC Signature...")
    valid = verify_file_signature(packed_bytes, signature, pk_sig)
    print(f"[+] Signature Valid: {valid}")

    # Log it
    entry = create_log_entry("SIGNATURE_VERIFIED", {"valid": valid})
    append_log(sign_log_entry(entry, pk_sig, pk_sig))

    if not valid:
        raise ValueError("[!] Signature verification failed — file rejected.")

    # DECRYPTION
    print("[*] Decrypting File...")
    plaintext = decrypt_packed_file(hybrid_key, packed_bytes)
    write_file_bytes(output_file, plaintext)
    print(f"[+] File decrypted successfully → {output_file}")

    # AUDIT LOG
    entry2 = create_log_entry("FILE_DECRYPTED", {"output": output_file, "bytes": len(plaintext)})
    append_log(sign_log_entry(entry2, pk_sig, pk_sig))

    print("[+] Audit Log Updated")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="QuantaCrypt — Hybrid QKD + PQC Encryption System")
    parser.add_argument("--encrypt", type=str, help="Encrypt and sign this file")
    parser.add_argument("--decrypt", type=str, help="Decrypt using stored ciphertext")

    parser.add_argument("--out", type=str, default="decrypted_output.bin", help="Output file for decrypted data")

    args = parser.parse_args()

    if args.encrypt:
        packaged, signature, pk_sig, hybrid_key = sender_encrypt_and_sign(args.encrypt)

        # Save artifacts for demo
        write_file_bytes("cipher_package.bin", packaged)
        write_file_bytes("cipher_signature.bin", signature)

        write_file_bytes("sender_pk_sig.bin", pk_sig)
        write_file_bytes("sender_hybrid_key.bin", hybrid_key)

        print("\n[+] Encryption complete. Files saved:\n"
              "- cipher_package.bin\n"
              "- cipher_signature.bin\n"
              "- sender_pk_sig.bin\n"
              "- sender_hybrid_key.bin\n")

    elif args.decrypt:
        packaged = read_file_bytes("cipher_package.bin")
        signature = read_file_bytes("cipher_signature.bin")
        pk_sig = read_file_bytes("sender_pk_sig.bin")
        hybrid_key = read_file_bytes("sender_hybrid_key.bin")

        receiver_verify_and_decrypt(packaged, signature, pk_sig, hybrid_key, args.out)

    else:
        print("Use:")
        print("  python main.py --encrypt myfile.pdf")
        print("  python main.py --decrypt --out result.pdf")
