# p2p_combined_plot_generator.py
# Reads results.json and generates ALL combined comparison plots

import json
import os
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D   # required for 3d projection

# ===============================================
# Load results.json
# ===============================================
RESULTS_FILE = "results.json"

with open(RESULTS_FILE, "r") as f:
    raw_data = json.load(f)

# Convert JSON keys to proper integers
data = {
    int(fsize): {int(peers): vals for peers, vals in fdata.items()}
    for fsize, fdata in raw_data.items()
}

FILE_SIZES = sorted(list(data.keys()))          # e.g. [1MB, 10MB, ...]
PEER_LOADS = sorted(list(data[FILE_SIZES[0]].keys()))  # e.g. [1,2,4,8...]

# Output directory
OUT_DIR = "p2p_combined_plots"
os.makedirs(OUT_DIR, exist_ok=True)

# ===============================================
# 1) Multi-line: Peers vs Latency (All File Sizes)
# ===============================================
plt.figure(figsize=(10,6))

for fs in FILE_SIZES:
    latencies = [data[fs][p]["avg_latency"] for p in PEER_LOADS]
    plt.plot(PEER_LOADS, latencies, marker='o', label=f"{fs/1e6:.1f} MB")

plt.xlabel("Peer Count")
plt.ylabel("Average Latency (s)")
plt.title("Peers vs Latency (Multiple File Sizes)")
plt.grid(True)
plt.legend()
plt.savefig(os.path.join(OUT_DIR, "combined_peers_vs_latency.png"), dpi=200)
plt.close()


# ===============================================
# 2) Multi-line: File Size vs Latency (All Peer Loads)
# ===============================================
plt.figure(figsize=(10,6))

for p in PEER_LOADS:
    sizes = [fs/1e6 for fs in FILE_SIZES]
    latencies = [data[fs][p]["avg_latency"] for fs in FILE_SIZES]
    plt.plot(sizes, latencies, marker='o', label=f"{p} peers")

plt.xlabel("File Size (MB)")
plt.ylabel("Average Latency (s)")
plt.title("File Size vs Latency (Multiple Peer Loads)")
plt.grid(True)
plt.legend()
plt.savefig(os.path.join(OUT_DIR, "combined_file_vs_latency.png"), dpi=200)
plt.close()


# ===============================================
# 3) 3D Surface Plot
# ===============================================
X, Y = np.meshgrid(PEER_LOADS, FILE_SIZES)
Z = np.zeros_like(X, dtype=float)

for i, fs in enumerate(FILE_SIZES):
    for j, p in enumerate(PEER_LOADS):
        Z[i, j] = data[fs][p]["avg_latency"]

fig = plt.figure(figsize=(12,8))
ax = fig.add_subplot(111, projection="3d")
ax.plot_surface(X, Y/1e6, Z, cmap="viridis")

ax.set_xlabel("Peer Count")
ax.set_ylabel("File Size (MB)")
ax.set_zlabel("Latency (s)")
ax.set_title("3D Surface: Latency vs Peers vs File Size")

plt.savefig(os.path.join(OUT_DIR, "surface_plot.png"), dpi=200)
plt.close()


# ===============================================
# 4) Contour Plot (Fixed)
# ===============================================
plt.figure(figsize=(10,6))

Y2D = np.array(FILE_SIZES).reshape(-1,1) / 1e6
Y2D = np.repeat(Y2D, len(PEER_LOADS), axis=1)

cont = plt.contourf(X, Y2D, Z, cmap="plasma")
plt.xlabel("Peer Count")
plt.ylabel("File Size (MB)")
plt.title("Contour Plot: Latency vs Peers vs File Size")
plt.colorbar(cont, label="Latency (s)")

plt.savefig(os.path.join(OUT_DIR, "contour_plot.png"), dpi=200)
plt.close()


# ===============================================
# 5) Heatmap
# ===============================================
plt.figure(figsize=(12,7))
plt.imshow(Z, cmap="inferno", aspect="auto")

plt.xticks(range(len(PEER_LOADS)), PEER_LOADS)
plt.yticks(range(len(FILE_SIZES)), [f"{fs/1e6:.1f} MB" for fs in FILE_SIZES])

plt.xlabel("Peer Count")
plt.ylabel("File Size")
plt.title("Heatmap: Latency Across Peers × File Sizes")
plt.colorbar(label="Latency (s)")

plt.savefig(os.path.join(OUT_DIR, "heatmap.png"), dpi=200)
plt.close()

print(f"[✓] ALL PLOTS GENERATED in '{OUT_DIR}/'")
