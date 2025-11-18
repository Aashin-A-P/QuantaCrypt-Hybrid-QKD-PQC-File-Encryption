import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from crypto_core.file_crypto import encrypt_file, decrypt_file
from hybrid_key.key_rotation import generate_new_hybrid_bundle


def run_file_crypto_test():
    print("\n=== FILE ENCRYPTION MODULE METRICS ===\n")

    # Get Hybrid Key Bundle
    _, _, bundle = generate_new_hybrid_bundle()
    hybrid_key = bundle.hybrid_key

    # Prepare test file
    test_input = "tests/test_input.txt"
    test_enc = "tests/encrypted.bin"
    test_dec = "tests/decrypted.txt"

    # Create a sample file
    with open(test_input, "w") as f:
        f.write("This is a sample test file for AES-GCM encryption.\n" * 2000)

    # Encryption
    enc_result = encrypt_file(test_input, test_enc, hybrid_key)
    print("[ENCRYPTION]")
    print("Input Size     :", enc_result["input_size"])
    print("Output Size    :", enc_result["output_size"])
    print("Nonce Used     :", enc_result["nonce"])
    print("Time (ms)      :", round(enc_result["encryption_time_ms"], 4))
    print()

    # Decryption
    dec_result = decrypt_file(test_enc, test_dec, hybrid_key)
    print("[DECRYPTION]")
    print("Recovered Size :", dec_result["plaintext_size"])
    print("Time (ms)      :", round(dec_result["decryption_time_ms"], 4))
    print()

    # Validate correctness
    with open(test_input, "rb") as f1, open(test_dec, "rb") as f2:
        same = f1.read() == f2.read()

    print("[VALIDATION] Files match:", same)


if __name__ == "__main__":
    run_file_crypto_test()
