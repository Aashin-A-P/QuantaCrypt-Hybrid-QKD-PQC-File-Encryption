import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import statistics
from qkd.qkd_simulator import (
    generate_qkd_key,
    generate_random_bits,
    generate_random_bases,
    sift_key,
)

print("\n=== QKD SIMULATOR METRICS ===\n")

def test_generation_speed(iterations=10):
    times = []
    for _ in range(iterations):
        start = time.time()
        generate_qkd_key()
        end = time.time()
        times.append(end - start)
    print("[METRIC] Key Generation Time")
    print(f"Average: {statistics.mean(times)*1000:.2f} ms")
    print(f"Min: {min(times)*1000:.2f} ms")
    print(f"Max: {max(times)*1000:.2f} ms\n")

def test_qber_normal(iterations=5):
    qbers = []
    for _ in range(iterations):
        _, q = generate_qkd_key()
        qbers.append(q)
    avg_qber = statistics.mean(qbers)
    print("[METRIC] QBER (Normal Channel)")
    print("Runs:", iterations)
    print("Individual QBERs:", [f"{q*100:.2f}%" for q in qbers])
    print(f"Average QBER: {avg_qber*100:.2f}%  (Expected: small, non-zero)\n")

def test_eve_attack(iterations=5):
    qbers = []
    for _ in range(iterations):
        _, q = generate_qkd_key(eve_attack=True, attack_prob=0.2)
        qbers.append(q)
    avg_qber = statistics.mean(qbers)
    print("[METRIC] QBER (With Eve Attack, 20%)")
    print("Runs:", iterations)
    print("Individual QBERs:", [f"{q*100:.2f}%" for q in qbers])
    print(f"Average QBER: {avg_qber*100:.2f}%  (Expected: clearly higher than normal)\n")

def test_sifted_ratio(raw_bits=1024):
    A_bits = generate_random_bits(raw_bits)
    A_bases = generate_random_bases(raw_bits)
    B_bases = generate_random_bases(raw_bits)
    _, matched_indices = sift_key(A_bits, A_bases, B_bases)
    ratio = len(matched_indices) / raw_bits
    print("[METRIC] Sifted Key Ratio")
    print(f"Sifted bits: {len(matched_indices)} / {raw_bits}")
    print(f"Ratio: {ratio*100:.2f}%  (Expected ~50%)\n")

def test_key_length():
    key, _ = generate_qkd_key()
    print("[METRIC] Final QKD Key Length")
    print(f"Length: {len(key)} bytes (Expected: 32 bytes)\n")

if __name__ == "__main__":
    test_generation_speed()
    test_qber_normal()
    test_eve_attack()
    test_sifted_ratio()
    test_key_length()
