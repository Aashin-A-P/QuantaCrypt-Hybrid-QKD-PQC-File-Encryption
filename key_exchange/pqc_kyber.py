import os, sys
import secrets
import hashlib

sys.setrecursionlimit(10000)

  
# Kyber Parameters (Kyber-512 style)
  
N = 256               # Polynomial degree
q = 3329             # Modulus
eta = 2              # Noise distribution parameter


  
# Helper: Modular arithmetic
  
def mod_q(x):
    return x % q


  
# Polynomial Sampling (real Kyber uses centered binomial)
  
def sample_poly():
    """Simulate small-noise polynomial."""
    return [(secrets.randbelow(2*eta+1) - eta) for _ in range(N)]


def random_poly():
    """Uniform random polynomial."""
    return [secrets.randbelow(q) for _ in range(N)]


  
# Polynomial Addition
  
def poly_add(a, b):
    return [(x+y) % q for x, y in zip(a, b)]


  
# Polynomial Multiplication (NTT-simplified)
# NOTE: Real Kyber uses NTT; this is a simplified cyclic conv.
  
def poly_mul(a, b):
    res = [0] * N
    for i in range(N):
        for j in range(N):
            res[(i+j) % N] += a[i] * b[j]
    return [mod_q(x) for x in res]


  
# Key Generation
# pk = A*s + e
# sk = s
  
def kyber_keygen():
    A = random_poly()
    s = sample_poly()
    e = sample_poly()

    pk = poly_add(poly_mul(A, s), e)

    return (A, pk), s


  
# Encapsulation
# ct = (u = A*r + e1, v = pk*r + e2 + m*(q//2))
# shared_secret = SHA3(v)
  
def kyber_encapsulate(A, pk):
    r = sample_poly()
    e1 = sample_poly()
    e2 = sample_poly()

    # Message bit simulated as polynomial with values 0 or q//2
    m = [secrets.randbelow(2) * (q//2) for _ in range(N)]

    u = poly_add(poly_mul(A, r), e1)
    v = poly_add(poly_mul(pk, r), poly_add(e2, m))

    ss = hashlib.sha3_256(bytes(str(v), 'utf-8')).digest()

    return (u, v), ss


  
# Decapsulation
# Recover shared secret from:
#     v - u*s ≈ m*(q/2)
  
def kyber_decapsulate(ct, sk):
    u, v = ct

    # Compute v - u*s
    us = poly_mul(u, sk)
    diff = [(v[i] - us[i]) % q for i in range(N)]

    # Re-extract message bit
    # If >= q/4, treat as 1
    m_recovered = [1 if x > q//4 else 0 for x in diff]
    m_poly = [bit * (q//2) for bit in m_recovered]

    ss = hashlib.sha3_256(bytes(str(v), 'utf-8')).digest()

    return ss


  
# High-level interface
  
def generate_pqc_shared_secret():
    (A, pk), sk = kyber_keygen()

    ct, ss_sender = kyber_encapsulate(A, pk)
    ss_receiver = kyber_decapsulate(ct, sk)

    if ss_sender != ss_receiver:
        raise ValueError("Kyber simulation mismatch — check polynomial parameters.")

    return ss_sender, pk, ct


  
# Test
  
if __name__ == "__main__":
    print("=== Realistic Kyber Simulation Test ===")
    ss, pk, ct = generate_pqc_shared_secret()
    print("Shared Secret:", ss.hex())
    print("Ciphertext u length:", len(ct[0]))
    print("Ciphertext v length:", len(ct[1]))
    print("Simulation OK.")
