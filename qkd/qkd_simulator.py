import secrets
import hashlib

def generate_random_bits(n):
    return [secrets.randbits(1) for _ in range(n)]

def generate_random_bases(n):
    return [secrets.randbits(1) for _ in range(n)]  # 0 = +, 1 = x

def eve_intercept(bits, bases, attack_probability=0.1):
    """
    Simulate Eve intercepting and measuring a fraction of qubits.
    She may change the state and/or basis before sending to B.
    """
    transmitted_bits = bits.copy()
    transmitted_bases = bases.copy()

    for i in range(len(bits)):
        if secrets.randbelow(100) < attack_probability * 100:
            eve_basis = secrets.randbits(1)
            # If Eve uses wrong basis, her measurement is random
            eve_bit = bits[i] if eve_basis == bases[i] else secrets.randbits(1)

            # She resends using her basis and measured bit
            transmitted_bits[i] = eve_bit
            transmitted_bases[i] = eve_basis

    return transmitted_bits, transmitted_bases

def measure_bits(transmitted_bits, transmitted_bases, B_bases):
    B_bits = []
    for t_bit, t_basis, b_basis in zip(transmitted_bits, transmitted_bases, B_bases):
        if t_basis == b_basis:
            B_bits.append(t_bit)
        else:
            B_bits.append(secrets.randbits(1))
    return B_bits

def sift_key(A_bits, A_bases, B_bases):
    sifted = []
    matched_indices = []
    for i, (a_bit, a_basis, b_basis) in enumerate(zip(A_bits, A_bases, B_bases)):
        if a_basis == b_basis:
            sifted.append(a_bit)
            matched_indices.append(i)
    return sifted, matched_indices

def calculate_qber(A_bits, B_bits, matched_indices):
    if not matched_indices:
        return 0.0
    errors = sum(1 for i in matched_indices if A_bits[i] != B_bits[i])
    return errors / len(matched_indices)

def privacy_amplification(sifted_bits, key_length=32):
    bitstring = ''.join(str(b) for b in sifted_bits)
    digest = hashlib.sha3_512(bitstring.encode()).digest()
    return digest[:key_length]

def generate_qkd_key(key_length_bytes=32, raw_bits=1024, eve_attack=False, attack_prob=0.1):
    """
    BB84-style QKD simulation with optional Eve.
    Returns: (K_QKD, qber)
    """

    # A's ORIGINAL bits and bases (what A *actually* sent)
    A_bits = generate_random_bits(raw_bits)
    A_bases = generate_random_bases(raw_bits)

    # What goes onto the channel (possibly modified by Eve)
    transmitted_bits = A_bits
    transmitted_bases = A_bases

    if eve_attack:
        transmitted_bits, transmitted_bases = eve_intercept(
            A_bits, A_bases, attack_probability=attack_prob
        )

    # B chooses bases
    B_bases = generate_random_bases(raw_bits)

    # B measures what arrives on the channel
    B_bits = measure_bits(transmitted_bits, transmitted_bases, B_bases)

    # Sifting based on A's original bases and B's bases
    sifted, matched_indices = sift_key(A_bits, A_bases, B_bases)

    # QBER: compare ORIGINAL A_bits vs B_bits on matched indices
    qber = calculate_qber(A_bits, B_bits, matched_indices)

    # Privacy amplification on sifted bits
    K_QKD = privacy_amplification(sifted, key_length_bytes)

    return K_QKD, qber
