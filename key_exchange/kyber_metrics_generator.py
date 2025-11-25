# kyber_metrics_generator.py

import time
import json
import os
import statistics
import matplotlib.pyplot as plt

from pqc_kyber import (
    kyber_generate_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    generate_pqc_shared_secret
)

BASE_DIR = "kyber_results"
PLOT_DIR = os.path.join(BASE_DIR, "plots")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

def run_kyber_metrics(runs=50):
    results = {
        "runs": runs,
        "metrics": []
    }

    for i in range(runs):
        print(f"[+] Run {i+1}/{runs}")

        t0 = time.time()
        pk_list, sk = kyber_generate_keypair()
        t1 = time.time()

        keypair_time = (t1 - t0) * 1000  # ms

        pk_size = len(pk_list)  # bytes

        t2 = time.time()
        ct_list, ss_sender = kyber_encapsulate(pk_list)
        t3 = time.time()

        encaps_time = (t3 - t2) * 1000
        ct_size = len(ct_list)

        t4 = time.time()
        ss_receiver = kyber_decapsulate(ct_list, sk, pk_list)
        t5 = time.time()

        decaps_time = (t5 - t4) * 1000

        kem_mismatch = ss_sender != ss_receiver

        t6 = time.time()
        final_key, _, _ = generate_pqc_shared_secret()
        t7 = time.time()

        final_key_time = (t7 - t6) * 1000
        final_key_size = len(final_key)

        # Store metrics
        results["metrics"].append({
            "keypair_time_ms": keypair_time,
            "encaps_time_ms": encaps_time,
            "decaps_time_ms": decaps_time,
            "final_key_time_ms": final_key_time,
            "pk_size": pk_size,
            "ct_size": ct_size,
            "final_key_size": final_key_size,
            "kem_mismatch": kem_mismatch
        })

    return results

def save_json(results):
    path = os.path.join(BASE_DIR, "results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Saved Kyber Metrics → {path}")

def plot_metric(results, metric_key, ylabel, title, filename):
    data = [m[metric_key] for m in results["metrics"]]

    plt.figure(figsize=(8,5))
    plt.plot(range(len(data)), data, marker='o', linestyle='-')

    plt.xlabel("Run Index", fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.title(title, fontsize=14)
    plt.grid(True)

    save_path = os.path.join(PLOT_DIR, filename)
    plt.savefig(save_path, dpi=200)
    plt.close()

    print(f"[+] Saved plot → {save_path}")

if __name__ == "__main__":
    print("Running Kyber Metrics Generator...")

    results = run_kyber_metrics(runs=50)
    save_json(results)

    # Plots
    plot_metric(results, "keypair_time_ms",
                "Time (ms)", "Kyber Keypair Generation Time",
                "kyber_keypair_time.png")

    plot_metric(results, "encaps_time_ms",
                "Time (ms)", "Kyber Encapsulation Time",
                "kyber_encapsulation_time.png")

    plot_metric(results, "decaps_time_ms",
                "Time (ms)", "Kyber Decapsulation Time",
                "kyber_decapsulation_time.png")

    plot_metric(results, "final_key_time_ms",
                "Time (ms)", "Final Hybrid-Ready Key Derivation Time",
                "kyber_final_key_time.png")

    print("\n[✓] ALL KYBER METRICS GENERATED SUCCESSFULLY!")
