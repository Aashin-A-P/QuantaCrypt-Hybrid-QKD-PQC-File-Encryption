# qkd_simulator.py — Enhanced BB84 QKD with QBER + Eve Attack Detection
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
from utils.hashing import sha3_512


# Random bit generator
def generate_random_bits(n: int):
    return [random.randint(0, 1) for _ in range(n)]


# Random bases: '+' or 'x'
def generate_random_bases(n: int):
    return [random.choice(['+', 'x']) for _ in range(n)]


# Eve intercept-resend attack
def eve_intercept(bits, bases, eve_enabled=False):
    if not eve_enabled:
        return bits, bases

    eve_bits = []
    eve_bases = generate_random_bases(len(bits))

    # Eve measures bits incorrectly if basis mismatch
    for b, s_base, e_base in zip(bits, bases, eve_bases):
        if s_base == e_base:
            eve_bits.append(b)
        else:
            eve_bits.append(random.randint(0, 1))

    # Eve resends with her random basis
    return eve_bits, eve_bases


# Measurement at receiver
def measure_bits(bits, sender_bases, receiver_bases):
    measured = []
    for b, s_base, r_base in zip(bits, sender_bases, receiver_bases):
        if s_base == r_base:
            measured.append(b)
        else:
            measured.append(random.randint(0, 1))
    return measured


# Sift key
def sift_key(sender_bases, receiver_bases, sender_bits, receiver_bits):
    sifted_sender = []
    sifted_receiver = []

    for s_b, r_b, s_bit, r_bit in zip(sender_bases, receiver_bases, sender_bits, receiver_bits):
        if s_b == r_b:
            sifted_sender.append(s_bit)
            sifted_receiver.append(r_bit)

    return sifted_sender, sifted_receiver


# QBER computation
def compute_qber(sift_s, sift_r):
    if len(sift_s) == 0:
        return 1.0  # total failure
    errors = sum(1 for a, b in zip(sift_s, sift_r) if a != b)
    return errors / len(sift_s)


# Convert bit array → bytes
def bits_to_bytes(bits):
    while len(bits) % 8 != 0:
        bits.append(0)

    output = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)


# FULL QKD PIPELINE
def run_qkd_key_exchange(bit_length: int = 256, eve=False):
    # 1. Sender bits + bases
    sender_bits = generate_random_bits(bit_length)
    sender_bases = generate_random_bases(bit_length)

    # 2. Eve intercepts (optional)
    intercepted_bits, intercepted_bases = eve_intercept(sender_bits, sender_bases, eve_enabled=eve)

    # 3. Receiver chooses bases
    receiver_bases = generate_random_bases(bit_length)

    # 4. Receiver measures
    receiver_bits = measure_bits(intercepted_bits, intercepted_bases if eve else sender_bases, receiver_bases)

    # 5. Sift matching-basis bits
    sift_s, sift_r = sift_key(sender_bases, receiver_bases, sender_bits, receiver_bits)

    # 6. QBER
    qber = compute_qber(sift_s, sift_r)

    # 7. If QBER too high → channel compromised
    compromised = qber > 0.20

    # 8. Privacy amplification
    final_key = sha3_512(bits_to_bytes(sift_s))[:32]

    return final_key, qber, compromised
