# crypto_metrics_generator.py

import os
import time
import json
import statistics
import matplotlib.pyplot as plt

from crypto_core.file_encryptor import encrypt_file_bytes
from crypto_core.file_decryptor import decrypt_packed_file
from crypto_core.file_packager import package_encrypted_file, unpack_encrypted_file


# ============================================================
# OUTPUT DIRECTORIES
# ============================================================
BASE_DIR = "crypto_results"
PLOT_DIR = os.path.join(BASE_DIR, "plots")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)


# ============================================================
# TEST FILE GENERATOR
# ============================================================
def generate_random_bytes(size):
    return os.urandom(size)


# ============================================================
# RUN METRICS
# ============================================================
def run_crypto_metrics(sizes = [
    1024,            # 1 KB
    10_000,          # 10 KB
    100_000,         # 100 KB
    1_000_000,       # 1 MB
    5_000_000,       # 5 MB
    10_000_000,      # 10 MB
    25_000_000,      # 25 MB
    50_000_000,      # 50 MB
    100_000_000      # 100 MB
]
, runs=10):
    results = {
        "file_sizes": sizes,
        "runs_per_case": runs,
        "metrics": {}
    }

    key = os.urandom(32)  # AES-256 key

    for size in sizes:
        print(f"\n=== Testing Crypto Metrics for size {size} bytes ===")
        results["metrics"][size] = {
            "encrypt_time_ms": [],
            "decrypt_time_ms": [],
            "package_time_ms": [],
            "unpack_time_ms": [],
            "throughput_MBps": [],
            "ciphertext_size": [],
            "package_size": []
        }

        for _ in range(runs):
            file_bytes = generate_random_bytes(size)

            # --------------------------
            # ENCRYPTION
            # --------------------------
            t1 = time.time()
            ciphertext, nonce, tag = encrypt_file_bytes(key, file_bytes)
            t2 = time.time()

            enc_time = (t2 - t1) * 1000
            results["metrics"][size]["encrypt_time_ms"].append(enc_time)

            # --------------------------
            # PACKAGING
            # --------------------------
            t3 = time.time()
            packaged = package_encrypted_file(ciphertext, nonce, tag, size)
            t4 = time.time()

            pack_time = (t4 - t3) * 1000
            results["metrics"][size]["package_time_ms"].append(pack_time)

            # Store sizes
            results["metrics"][size]["ciphertext_size"].append(len(ciphertext))
            results["metrics"][size]["package_size"].append(len(packaged))

            # --------------------------
            # UNPACK
            # --------------------------
            t5 = time.time()
            version, n, t, orig_size, cipher = unpack_encrypted_file(packaged)
            t6 = time.time()

            unpack_time = (t6 - t5) * 1000
            results["metrics"][size]["unpack_time_ms"].append(unpack_time)

            # --------------------------
            # DECRYPTION
            # --------------------------
            t7 = time.time()
            dec = decrypt_packed_file(key, packaged)
            t8 = time.time()

            dec_time = (t8 - t7) * 1000
            results["metrics"][size]["decrypt_time_ms"].append(dec_time)

            # --------------------------
            # THROUGHPUT
            # --------------------------
            throughput = (size / (enc_time / 1000)) / (1024 * 1024)
            results["metrics"][size]["throughput_MBps"].append(throughput)

    return results


# ============================================================
# SAVE JSON
# ============================================================
def save_json(results):
    path = os.path.join(BASE_DIR, "results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Saved crypto results → {path}")


# ============================================================
# PLOTTING HELPERS
# ============================================================
def plot_metric(results, metric, ylabel, title, filename):
    sizes = results["file_sizes"]
    averages = []

    for size in sizes:
        values = results["metrics"][size][metric]
        averages.append(statistics.mean(values))

    plt.figure(figsize=(8,5))
    plt.plot([s/1024 for s in sizes], averages, marker='o')
    plt.xlabel("File Size (KB)", fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.title(title, fontsize=14)
    plt.grid(True)

    save_path = os.path.join(PLOT_DIR, filename)
    plt.savefig(save_path, dpi=200)
    plt.close()

    print(f"[+] Saved plot → {save_path}")


# ============================================================
# MAIN EXECUTION
# ============================================================
if __name__ == "__main__":
    print("\nRunning Crypto Metrics Generator...\n")

    results = run_crypto_metrics()
    save_json(results)

    # Important Plots
    plot_metric(results, "encrypt_time_ms", "Time (ms)", "AES-GCM Encryption Time", "aes_enc_time.png")
    plot_metric(results, "decrypt_time_ms", "Time (ms)", "AES-GCM Decryption Time", "aes_dec_time.png")
    plot_metric(results, "package_time_ms", "Time (ms)", "Packaging Overhead", "package_time.png")
    plot_metric(results, "unpack_time_ms", "Time (ms)", "Unpack Overhead", "unpack_time.png")
    plot_metric(results, "throughput_MBps", "Throughput (MB/s)", "AES-GCM Throughput", "aes_throughput.png")

    print("\n[✓] All crypto metrics generated successfully!")
