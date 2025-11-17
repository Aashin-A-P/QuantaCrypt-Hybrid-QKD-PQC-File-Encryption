import secrets
import hashlib

# ------------------------------------------------------------
#  Generate random bits and bases
# ------------------------------------------------------------

def generate_random_bits(n):
    """Generate random 0/1 bits for A."""
    return [secrets.randbits(1) for _ in range(n)]

def generate_random_bases(n):
    """Generate random measurement bases: 0 = + (rectilinear), 1 = x (diagonal)."""
    return [secrets.randbits(1) for _ in range(n)]


# ------------------------------------------------------------
#  Eve Attack Simulation
# ------------------------------------------------------------

def eve_intercept(bits, bases, attack_probability=0.1):
    """
    Simulate Eve intercepting and measuring a fraction of qubits.
    attack_probability: 0.1 means 10% of bits are intercepted.
    """
    intercepted_bits = bits.copy()
    intercepted_bases = bases.copy()

    for i in range(len(bits)):
        if secrets.randbelow(100) < attack_probability * 100:
            # Eve chooses a random basis to measure
            eve_basis = secrets.randbits(1)
            eve_bit = secrets.randbits(1) if eve_basis != bases[i] else bits[i]
            
            # Eve resends with her basis + measurement
            intercepted_bits[i] = eve_bit
            intercepted_bases[i] = eve_basis

    return intercepted_bits, intercepted_bases


# ------------------------------------------------------------
#  Bob Measurement Simulation
# ------------------------------------------------------------

def measure_bits(A_bits, A_bases, B_bases):
    """Simulate B's measurement of A's photons."""
    B_bits = []
    for a_bit, a_basis, b_basis in zip(A_bits, A_bases, B_bases):
        if a_basis == b_basis:
            B_bits.append(a_bit)
        else:
            B_bits.append(secrets.randbits(1))  # random due to mismatch
    return B_bits


# ------------------------------------------------------------
#  Sifting & QBER
# ------------------------------------------------------------

def sift_key(A_bits, A_bases, B_bases):
    """Keep only bits where bases match."""
    sifted = []
    matched_indices = []
    for i, (a_bit, a_basis, b_basis) in enumerate(zip(A_bits, A_bases, B_bases)):
        if a_basis == b_basis:
            sifted.append(a_bit)
            matched_indices.append(i)
    return sifted, matched_indices


def calculate_qber(A_bits, B_bits, matched_indices):
    """Quantum Bit Error Rate = errors / matched bits."""
    if not matched_indices:
        return 0.0
    
    errors = sum(1 for i in matched_indices if A_bits[i] != B_bits[i])
    return errors / len(matched_indices)


# ------------------------------------------------------------
#  Privacy Amplification
# ------------------------------------------------------------

def privacy_amplification(sifted_bits, key_length=32):
    """Hash sifted bits into a final key of length key_length bytes."""
    bitstring = ''.join(str(b) for b in sifted_bits)
    digest = hashlib.sha3_512(bitstring.encode()).digest()
    return digest[:key_length]


# ------------------------------------------------------------
#  Full QKD Simulation + Optional Eve Attack
# ------------------------------------------------------------

def generate_qkd_key(key_length_bytes=32, raw_bits=1024, eve_attack=False, attack_prob=0.1):
    """
    BB84 QKD simulation.
    Supports optional Eve attack simulation.
    Returns: (K_QKD, QBER)
    """

    # Step 1: A prepares bits & bases
    A_bits = generate_random_bits(raw_bits)
    A_bases = generate_random_bases(raw_bits)

    # Step 2: Eve may intercept
    if eve_attack:
        A_bits, A_bases = eve_intercept(A_bits, A_bases, attack_prob)

    # Step 3: B chooses bases
    B_bases = generate_random_bases(raw_bits)

    # Step 4: Measurement simulation
    B_bits = measure_bits(A_bits, A_bases, B_bases)

    # Step 5: Sifting
    sifted, matched_indices = sift_key(A_bits, A_bases, B_bases)

    # Step 6: QBER calculation
    qber = calculate_qber(A_bits, B_bits, matched_indices)

    # Step 7: Privacy Amplification
    K_QKD = privacy_amplification(sifted, key_length_bytes)

    return K_QKD, qber
