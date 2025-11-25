# qkd_metrics_generator.py
import time
import json
import os
import statistics
import matplotlib.pyplot as plt

from qkd_simulator import run_qkd_key_exchange

BASE_DIR = "qkd_metrics"
PLOT_DIR = os.path.join(BASE_DIR, "plots")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

def run_metrics(bit_lengths, runs_per_case=20):
    results = {
        "bit_lengths": bit_lengths,
        "runs_per_case": runs_per_case,
        "metrics": {}
    }

    for bits in bit_lengths:
        results["metrics"][bits] = {
            "no_eve": [],
            "eve": []
        }

        print(f"\n=== Running QKD metrics for bit_length = {bits} ===")

        for _ in range(runs_per_case):
            start = time.time()
            key, qber, compromised = run_qkd_key_exchange(bits, eve=False)
            end = time.time()

            entry = {
                "qber": qber,
                "compromised": compromised,
                "exec_time_ms": round((end - start) * 1000, 5),
                "sifted_key_length": len(key)
            }
            results["metrics"][bits]["no_eve"].append(entry)

        for _ in range(runs_per_case):
            start = time.time()
            key, qber, compromised = run_qkd_key_exchange(bits, eve=True)
            end = time.time()

            entry = {
                "qber": qber,
                "compromised": compromised,
                "exec_time_ms": round((end - start) * 1000, 5),
                "sifted_key_length": len(key)
            }
            results["metrics"][bits]["eve"].append(entry)

    return results

def save_json(results):
    path = os.path.join(BASE_DIR, "results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Saved QKD Metrics → {path}")

def plot_metric(results, metric, ylabel, title, filename):
    plt.figure(figsize=(8,5))

    bit_lengths = results["bit_lengths"]

    no_eve_vals = []
    eve_vals = []

    for bits in bit_lengths:
        no_eve = [r[metric] for r in results["metrics"][bits]["no_eve"]]
        eve = [r[metric] for r in results["metrics"][bits]["eve"]]

        no_eve_vals.append(statistics.mean(no_eve))
        eve_vals.append(statistics.mean(eve))

    plt.plot(bit_lengths, no_eve_vals, marker="o", label="No Eve")
    plt.plot(bit_lengths, eve_vals, marker="o", label="Eve Intercept")

    plt.xlabel("Bit Length", fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.title(title, fontsize=14)
    plt.grid(True)
    plt.legend()

    save_path = os.path.join(PLOT_DIR, filename)
    plt.savefig(save_path, dpi=200)
    plt.close()

    print(f"[+] Saved plot → {save_path}")


if __name__ == "__main__":
    bit_lengths = [128, 256, 512, 1024]

    print("Running QKD Metrics Generator...")

    results = run_metrics(bit_lengths, runs_per_case=20)
    save_json(results)

    plot_metric(results, "qber",
                "QBER", "QBER vs Bit Length",
                "qber_vs_bit_length.png")

    plot_metric(results, "exec_time_ms",
                "Execution Time (ms)", "QKD Execution Time vs Bit Length",
                "exec_time_vs_bit_length.png")

    plot_metric(results, "sifted_key_length",
                "Final Key Length (bytes)", "Sifted Key Size vs Bit Length",
                "sifted_vs_bit_length.png")

    print("\n[✓] ALL METRICS GENERATED SUCCESSFULLY!")
