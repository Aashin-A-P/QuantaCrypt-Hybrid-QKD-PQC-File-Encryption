import secrets
import hashlib

def generate_random_bits(n):
    """Generate random 0/1 bits for A."""
    return [secrets.randbits(1) for _ in range(n)]

def generate_random_bases(n):
    """Generate random measurement bases: 0 = + (rectilinear), 1 = x (diagonal)."""
    return [secrets.randbits(1) for _ in range(n)]  # 0=+, 1=x

def measure_bits(A_bits, A_bases, B_bases):
    """Simulate B's measurement of A's photons."""
    B_bits = []
    for a_bit, a_basis, b_basis in zip(A_bits, A_bases, B_bases):
        if a_basis == b_basis:
            B_bits.append(a_bit)      # Correct measurement
        else:
            B_bits.append(secrets.randbits(1))  # Wrong basis → random bit
    return B_bits

def sift_key(A_bits, A_bases, B_bases):
    """Sift the key by keeping only matched bases."""
    sifted = []
    for a_bit, a_basis, b_basis in zip(A_bits, A_bases, B_bases):
        if a_basis == b_basis:
            sifted.append(a_bit)
    return sifted

def privacy_amplification(sifted_bits, key_length=32):
    """
    Apply SHA3-512 to compress the sifted key into a high-entropy final key.
    key_length is in bytes (32 = 256-bit).
    """
    bitstring = ''.join(str(b) for b in sifted_bits)
    digest = hashlib.sha3_512(bitstring.encode()).digest()
    return digest[:key_length]

def generate_qkd_key(key_length_bytes=32, raw_bits=1024):
    """
    Full BB84-style QKD key simulation.
    Returns: K_QKD (high-entropy symmetric key)
    """

    # Step 1: A generates bits and bases
    A_bits = generate_random_bits(raw_bits)
    A_bases = generate_random_bases(raw_bits)

    # Step 2: B randomly selects bases to measure incoming photons
    B_bases = generate_random_bases(raw_bits)

    # Step 3: Measurement simulation (not used further but kept for completeness)
    _ = measure_bits(A_bits, A_bases, B_bases)

    # Step 4: Sifting - Only keep positions where A and B used same basis
    sifted = sift_key(A_bits, A_bases, B_bases)

    # Step 5: Privacy amplification - Hash to produce final key
    K_QKD = privacy_amplification(sifted, key_length_bytes)

    return K_QKD
