import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import statistics
import matplotlib.pyplot as plt

from qkd.qkd_simulator import (
    generate_qkd_key,
    generate_random_bits,
    generate_random_bases,
    measure_bits,
    sift_key
)

# -------------------------------------------------------------------
# Create output folder for plots
# -------------------------------------------------------------------
PLOT_DIR = "plots/qkd_plots"
os.makedirs(PLOT_DIR, exist_ok=True)

# -------------------------------------------------------------------
# Helper to save plot
# -------------------------------------------------------------------
def save_plot(name):
    plt.savefig(os.path.join(PLOT_DIR, name), dpi=300, bbox_inches='tight')
    plt.close()


# ===================================================================
# 1. QBER vs Attack Probability (Line Graph)
# ===================================================================
def plot_qber_vs_attack_prob():
    attack_probs = [0.0, 0.05, 0.1, 0.2, 0.3, 0.4]
    qbers = []

    for p in attack_probs:
        _, qber = generate_qkd_key(eve_attack=True if p > 0 else False, attack_prob=p)
        qbers.append(qber * 100)  # convert to %

    plt.figure(figsize=(7, 4))
    plt.plot(attack_probs, qbers, marker='o', linestyle='-', color='blue')
    plt.title("QBER vs Attack Probability")
    plt.xlabel("Attack Probability")
    plt.ylabel("QBER (%)")
    plt.grid(True)
    save_plot("qber_vs_attack_probability.png")


# ===================================================================
# 2. Sifted Bits Distribution (Bar Chart)
# ===================================================================
def plot_sifted_bit_distribution(raw_bits=1024):
    A_bits = generate_random_bits(raw_bits)
    A_bases = generate_random_bases(raw_bits)
    B_bases = generate_random_bases(raw_bits)

    sifted, _ = sift_key(A_bits, A_bases, B_bases)

    plt.figure(figsize=(6, 4))
    plt.bar(["Raw Bits", "Sifted Bits"], [raw_bits, len(sifted)], color=["gray", "green"])
    plt.title("Sifted Bits Distribution (BB84)")
    plt.ylabel("Number of Bits")
    save_plot("sifted_bits_distribution.png")


# ===================================================================
# 3. Random Bit Frequency Histogram
# ===================================================================
def plot_random_bit_histogram(raw_bits=2048):
    bits = generate_random_bits(raw_bits)
    zeros = bits.count(0)
    ones = bits.count(1)

    plt.figure(figsize=(6, 4))
    plt.bar(["0", "1"], [zeros, ones], color=["black", "orange"])
    plt.title("Random Bit Distribution")
    plt.ylabel("Count")
    save_plot("random_bit_histogram.png")


# ===================================================================
# 4. Key Generation Time (Bar Chart)
# ===================================================================
def plot_key_gen_time(iterations=10):
    times = []
    for _ in range(iterations):
        start = time.time()
        generate_qkd_key()
        end = time.time()
        times.append((end - start) * 1000)  # convert to ms

    plt.figure(figsize=(7, 4))
    plt.bar(range(1, iterations+1), times, color="purple")
    plt.title("QKD Key Generation Time per Run")
    plt.xlabel("Run #")
    plt.ylabel("Time (ms)")
    save_plot("key_generation_time.png")


# ===================================================================
# 5. QBER Clean vs Eve (Bar Comparison)
# ===================================================================
def plot_qber_clean_vs_eve():
    # Clean
    _, q_clean = generate_qkd_key()

    # Eve Attack (20%)
    _, q_eve = generate_qkd_key(eve_attack=True, attack_prob=0.2)

    plt.figure(figsize=(6, 4))
    plt.bar(["Clean Channel", "Eve Attack"], [q_clean * 100, q_eve * 100], color=["green", "red"])
    plt.title("QBER Comparison: Clean vs Eve Attack")
    plt.ylabel("QBER (%)")
    save_plot("qber_clean_vs_eve.png")


# ===================================================================
# MAIN - Generate all plots
# ===================================================================
if __name__ == "__main__":
    print("Generating QKD plots...")

    plot_qber_vs_attack_prob()
    print("✓ QBER vs Attack Probability")

    plot_sifted_bit_distribution()
    print("✓ Sifted Bits Distribution")

    plot_random_bit_histogram()
    print("✓ Random Bit Distribution")

    plot_key_gen_time()
    print("✓ Key Generation Time Plot")

    plot_qber_clean_vs_eve()
    print("✓ Clean vs Eve Attack QBER Plot")

    print("\nAll plots saved in 'plots/' folder.")
