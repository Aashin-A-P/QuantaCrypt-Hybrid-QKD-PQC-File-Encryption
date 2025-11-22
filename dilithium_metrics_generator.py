# dilithium_metrics_generator.py

import os
import time
import json
import statistics
import matplotlib.pyplot as plt

from pqc_signature.dilithium_sign import (
    generate_sig_keypair,
    sign_message,
)
from pqc_signature.dilithium_verify import (
    verify_signature,
)


# ============================================================
# OUTPUT DIRECTORIES
# ============================================================
BASE_DIR = "dilithium_results"
PLOT_DIR = os.path.join(BASE_DIR, "plots")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)


# ============================================================
# RANDOM MESSAGE GENERATOR
# ============================================================
def generate_message(size):
    return os.urandom(size)


# ============================================================
# RUN METRICS
# ============================================================
def run_dilithium_metrics(sizes=[1024, 10_000, 100_000, 1_000_000], runs=20):

    results = {
        "message_sizes": sizes,
        "runs_per_case": runs,
        "metrics": {}
    }

    for size in sizes:
        print(f"\n=== Running signature metrics for message size {size} bytes ===")

        results["metrics"][size] = {
            "keypair_time_ms": [],
            "sign_time_ms": [],
            "verify_time_ms": [],
            "pk_size": [],
            "sk_size": [],
            "sig_size": [],
            "verify_success": [],
            "verify_failure": []
        }

        for _ in range(runs):

            # ----------------------------
            # KEYPAR GENERATION
            # ----------------------------
            t1 = time.time()
            pk, sk = generate_sig_keypair()
            t2 = time.time()
            keypair_ms = (t2 - t1) * 1000

            results["metrics"][size]["keypair_time_ms"].append(keypair_ms)
            results["metrics"][size]["pk_size"].append(len(pk))
            results["metrics"][size]["sk_size"].append(len(sk))

            # ----------------------------
            # SIGNATURE GENERATION
            # ----------------------------
            message = generate_message(size)

            t3 = time.time()
            sig = sign_message(message, sk)
            t4 = time.time()
            sign_ms = (t4 - t3) * 1000

            results["metrics"][size]["sign_time_ms"].append(sign_ms)
            results["metrics"][size]["sig_size"].append(len(sig))

            # ----------------------------
            # VERIFICATION
            # ----------------------------
            t5 = time.time()
            ok = verify_signature(message, sig, pk)
            t6 = time.time()
            verify_ms = (t6 - t5) * 1000

            results["metrics"][size]["verify_time_ms"].append(verify_ms)
            results["metrics"][size]["verify_success"].append(ok)

            # ----------------------------
            # NEGATIVE TEST (TAMPERED)
            # ----------------------------
            tampered_msg = message + b"x"
            wrong = verify_signature(tampered_msg, sig, pk)
            results["metrics"][size]["verify_failure"].append(wrong)

    return results


# ============================================================
# SAVE JSON
# ============================================================
def save_json(results):
    fname = os.path.join(BASE_DIR, "results.json")
    with open(fname, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[✓] Saved results → {fname}")


# ============================================================
# PLOTTING
# ============================================================
def plot_metric(results, metric_key, ylabel, title, filename):

    sizes = results["message_sizes"]
    averages = []

    for s in sizes:
        averages.append(statistics.mean(results["metrics"][s][metric_key]))

    plt.figure(figsize=(8,5))
    plt.plot([x/1024 for x in sizes], averages, marker='o')
    plt.grid(True)
    plt.xlabel("Message Size (KB)")
    plt.ylabel(ylabel)
    plt.title(title)

    save_path = os.path.join(PLOT_DIR, filename)
    plt.savefig(save_path, dpi=200)
    plt.close()

    print(f"[+] Plot saved → {save_path}")


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":

    results = run_dilithium_metrics()
    save_json(results)

    plot_metric(results, "keypair_time_ms", "ms",
                "Keypair Generation Time", "keypair_time.png")

    plot_metric(results, "sign_time_ms", "ms",
                "Signature Generation Time", "sign_time.png")

    plot_metric(results, "verify_time_ms", "ms",
                "Signature Verification Time", "verify_time.png")

    plot_metric(results, "sig_size", "bytes",
                "Signature Size", "sig_size.png")

    print("\n[✓] All Dilithium-inspired signature metrics generated!")
