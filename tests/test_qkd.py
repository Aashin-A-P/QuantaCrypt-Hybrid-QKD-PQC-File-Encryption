import time
import secrets
import statistics
from qkd.qkd_simulator import (
    generate_random_bits,
    generate_random_bases,
    measure_bits,
    sift_key,
    privacy_amplification,
    generate_qkd_key
)

# ---------------------------
# Metric 1: Key Generation Time
# ---------------------------
def test_key_generation_speed(iterations=10):
    times = []
    for _ in range(iterations):
        start = time.time()
        generate_qkd_key()
        end = time.time()
        times.append(end - start)
    print("\n[METRIC] Key Generation Time")
    print(f"Average: {statistics.mean(times)*1000:.2f} ms")
    print(f"Min: {min(times)*1000:.2f} ms")
    print(f"Max: {max(times)*1000:.2f} ms\n")

# ---------------------------
# Metric 2: Sifted Key Length Ratio
# ---------------------------
def test_sifted_key_ratio(raw_bits=1024):
    A_bits = generate_random_bits(raw_bits)
    A_bases = generate_random_bases(raw_bits)
    B_bases = generate_random_bases(raw_bits)

    sifted = sift_key(A_bits, A_bases, B_bases)

    ratio = len(sifted) / raw_bits
    print("[METRIC] Sifted Key Ratio")
    print(f"Sifted bits: {len(sifted)} / {raw_bits}")
    print(f"Ratio: {ratio*100:.2f}% (Expected ~50%)\n")

# ---------------------------
# Metric 3: Randomness Test (Byte Uniqueness)
# ---------------------------
def test_key_randomness(iterations=5):
    keys = [generate_qkd_key() for _ in range(iterations)]
    unique_keys = len(set(k for k in keys))
    print("[METRIC] Randomness Test")
    print(f"Generated Keys: {iterations}")
    print(f"Unique Keys:    {unique_keys}")
    if unique_keys == iterations:
        print("Status: PASS (All keys unique)\n")
    else:
        print("Status: FAIL (Duplicate key detected)\n")

# ---------------------------
# Metric 4: Bit Distribution Test
# ---------------------------
def test_bit_distribution(raw_bits=2048):
    bits = generate_random_bits(raw_bits)
    ones = bits.count(1)
    zeros = bits.count(0)

    print("[METRIC] Bit Distribution")
    print(f"Total bits: {raw_bits}")
    print(f"0s: {zeros} ({(zeros/raw_bits)*100:.2f}%)")
    print(f"1s: {ones} ({(ones/raw_bits)*100:.2f}%)")
    print("Expected: ~50% distribution each\n")

# ---------------------------
# Metric 5: Final Key Length
# ---------------------------
def test_final_key_length():
    key = generate_qkd_key()
    print("[METRIC] Final QKD Key Length")
    print(f"Length: {len(key)} bytes (Expected: 32 bytes)\n")

# ---------------------------
#     RUN ALL METRICS
# ---------------------------
if __name__ == "__main__":
    print("=== QKD Simulator Metrics ===\n")
    test_key_generation_speed()
    test_sifted_key_ratio()
    test_key_randomness()
    test_bit_distribution()
    test_final_key_length()
