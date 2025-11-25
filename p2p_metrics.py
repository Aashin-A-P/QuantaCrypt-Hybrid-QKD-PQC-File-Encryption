import os
import time
import json
import statistics
import subprocess
import random
import matplotlib.pyplot as plt

BASE_DIR = "p2p_simple_results"
PLOT_DIR = os.path.join(BASE_DIR, "plots")
os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

FILE_SIZES = [
    1_000_000,          # 1 MB
    10_000_000,         # 10 MB
    50_000_000,         # 50 MB
    100_000_000,        # 100 MB
    250_000_000,        # 250 MB
    500_000_000,        # 500 MB
    1_000_000_000       # 1 GB
]

PEER_LOADS = [1, 2, 4, 8, 16, 32, 64]


def run_single_transfer(file_path, recv_port, sender_port):
    """Runs ONE actual P2P transfer through peer.py and measures latency."""

    recv = subprocess.Popen(
        ["python", "peer.py", str(recv_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(1.2)  # allow bind

    start = time.time()

    sender = subprocess.Popen(
        ["python", "peer.py", str(sender_port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    cmd = f"1\n127.0.0.1:{recv_port}\n{file_path}\n"
    sender.stdin.write(cmd.encode())
    sender.stdin.flush()

    sender.wait()
    latency = time.time() - start

    recv.kill()
    recv.wait()

    return latency


def run_metrics():
    results = {}

    for file_size in FILE_SIZES:

        print(f"\n=== Testing file size: {file_size/1e6:.1f} MB ===")

        test_file = "p2p_test.bin"
        with open(test_file, "wb") as f:
            f.write(os.urandom(file_size))

        results[file_size] = {}

        for load in PEER_LOADS:
            print(f"  → Simulated peers: {load}")

            latencies = []

            for i in range(load):
                recv_port = 8000 + random.randint(0, 2000)
                sender_port = 10000 + random.randint(0, 2000)

                lat = run_single_transfer(test_file, recv_port, sender_port)
                latencies.append(lat)

            results[file_size][load] = {
                "avg_latency": statistics.mean(latencies),
                "min_latency": min(latencies),
                "max_latency": max(latencies),
                "std_latency": statistics.stdev(latencies) if len(latencies) > 1 else 0,
                "all_latencies": latencies
            }

            print(f"     Avg latency = {statistics.mean(latencies):.3f}s")

        os.remove(test_file)

    return results

def plot_peer_vs_latency(results):
    for file_size, data in results.items():
        peers = []
        avg_lat = []

        for p in PEER_LOADS:
            peers.append(p)
            avg_lat.append(data[p]["avg_latency"])

        plt.figure(figsize=(8, 5))
        plt.plot(peers, avg_lat, marker='o')
        plt.xlabel("Simulated Peer Load")
        plt.ylabel("Average Latency (s)")
        plt.title(f"P2P Latency vs Peer Load (File Size = {file_size/1e6:.1f} MB)")
        plt.grid(True)

        out = os.path.join(PLOT_DIR, f"latency_vs_peers_{file_size}.png")
        plt.savefig(out, dpi=200)
        plt.close()
        print(f"[+] Saved plot → {out}")


def plot_file_size_vs_latency(results):
    for load in PEER_LOADS:
        sizes = []
        lat = []

        for file_size in FILE_SIZES:
            sizes.append(file_size / 1e6)
            lat.append(results[file_size][load]["avg_latency"])

        plt.figure(figsize=(8, 5))
        plt.plot(sizes, lat, marker='o')
        plt.xlabel("File Size (MB)")
        plt.ylabel("Average Latency (s)")
        plt.title(f"P2P Latency vs File Size (Simulated {load} peers)")
        plt.grid(True)

        out = os.path.join(PLOT_DIR, f"latency_vs_file_{load}_peers.png")
        plt.savefig(out, dpi=200)
        plt.close()
        print(f"[+] Saved plot → {out}")


def plot_box_latency(results):
    for file_size, data in results.items():
        plt.figure(figsize=(8, 5))
        plt.boxplot([data[p]["all_latencies"] for p in PEER_LOADS], labels=PEER_LOADS)
        plt.xlabel("Simulated Peer Count")
        plt.ylabel("Latency Distribution (s)")
        plt.title(f"P2P Latency Distribution (File Size = {file_size/1e6:.1f} MB)")
        plt.grid(True)

        out = os.path.join(PLOT_DIR, f"box_latency_{file_size}.png")
        plt.savefig(out, dpi=200)
        plt.close()
        print(f"[+] Saved plot → {out}")


if __name__ == "__main__":
    print("\nRunning SIMPLE P2P Metrics...\n")

    results = run_metrics()

    out_file = os.path.join(BASE_DIR, "results.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[✓] Saved results → {out_file}")

    print("\nGenerating plots...\n")
    plot_peer_vs_latency(results)
    plot_file_size_vs_latency(results)
    plot_box_latency(results)

    print("\n[✓] All P2P simple metrics + plots generated successfully!")
