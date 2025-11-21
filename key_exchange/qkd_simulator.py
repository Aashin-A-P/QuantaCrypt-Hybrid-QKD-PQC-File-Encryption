# qkd_simulator.py — Simulated BB84 Quantum Key Distribution
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
import random
from utils.hashing import sha3_512

# Generate random bits
def generate_random_bits(n: int):
    return [random.randint(0, 1) for _ in range(n)]

# Generate random polarization bases (+ or ×)
def generate_random_bases(n: int):
    return [random.choice(['+', 'x']) for _ in range(n)]

# Measure photon based on sender/receiver bases
def measure_bits(bits, sender_bases, receiver_bases):
    measured = []
    for b, s_base, r_base in zip(bits, sender_bases, receiver_bases):
        if s_base == r_base:
            measured.append(b)   # Correct measurement
        else:
            measured.append(random.randint(0, 1))  # Random
    return measured

# Sift keys by comparing bases
def sift_key(sender_bases, receiver_bases, sender_bits, receiver_bits):
    sifted = []
    for s_b, r_b, s_bit, r_bit in zip(sender_bases, receiver_bases, sender_bits, receiver_bits):
        if s_b == r_b:
            sifted.append(s_bit)
    return sifted

# Convert bit list → bytes
def bits_to_bytes(bits):
    # pad to multiple of 8
    while len(bits) % 8 != 0:
        bits.append(0)

    output = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)

# Full QKD handshake (Simulation)

def run_qkd_key_exchange(bit_length: int = 256) -> bytes:
    # 1. Random bits & bases
    sender_bits = generate_random_bits(bit_length)
    sender_bases = generate_random_bases(bit_length)

    # 2. Receiver bases
    receiver_bases = generate_random_bases(bit_length)

    # 3. Receiver measures photons
    receiver_bits = measure_bits(sender_bits, sender_bases, receiver_bases)

    # 4. Sift key (matching bases only)
    sifted = sift_key(sender_bases, receiver_bases, sender_bits, receiver_bits)

    # 5. Convert to bytes
    sifted_bytes = bits_to_bytes(sifted)

    # 6. Privacy amplification (SHA3-512 → 32 bytes output)
    final_key = sha3_512(sifted_bytes)[:32]

    return final_key
