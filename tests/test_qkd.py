import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import statistics
from qkd.qkd_simulator import (
    generate_qkd_key,
    generate_random_bits,
    generate_random_bases,
    measure_bits,
    sift_key,
    calculate_qber
)

print("\n=== QKD SIMULATOR METRICS ===\n")

# ----------------------------------------------------------------
# 1. Test QKD Key Generation Speed
# ----------------------------------------------------------------
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

# ----------------------------------------------------------------
# 2. Test QBER (Normal Channel)
# ----------------------------------------------------------------
def test_qber_normal():
    _, qber = generate_qkd_key()
    print("[METRIC] QBER (Normal Channel)")
    print(f"QBER: {qber*100:.2f}%  (Expected: ~2–5%)\n")

# ----------------------------------------------------------------
# 3. Test QBER Under Eve Attack
# ----------------------------------------------------------------
def test_eve_attack():
    _, qber = generate_qkd_key(eve_attack=True, attack_prob=0.2)
    print("[METRIC] QBER (With Eve Attack 20%)")
    print(f"QBER: {qber*100:.2f}%  (Expected: High > 10%)\n")

# ----------------------------------------------------------------
# 4. Sifted Key Length Ratio
# ----------------------------------------------------------------
def test_sifted_ratio():
    raw_bits = 1024
    A_bits = generate_random_bits(raw_bits)
    A_bases = generate_random_bases(raw_bits)
    B_bases = generate_random_bases(raw_bits)
    _, matched = sift_key(A_bits, A_bases, B_bases)
    ratio = len(matched) / raw_bits
    print("[METRIC] Sifted Key Ratio")
    print(f"Sifted bits: {len(matched)} / {raw_bits}")
    print(f"Ratio: {ratio*100:.2f}%  (Expected ~50%)\n")

# ----------------------------------------------------------------
# 5. Final Key Length
# ----------------------------------------------------------------
def test_key_length():
    key, _ = generate_qkd_key()
    print("[METRIC] Final QKD Key Length")
    print(f"Length: {len(key)} bytes (Expected: 32 bytes)\n")

# ----------------------------------------------------------------
# Run All Tests
# ----------------------------------------------------------------
if __name__ == "__main__":
    test_generation_speed()
    test_qber_normal()
    test_eve_attack()
    test_sifted_ratio()
    test_key_length()
