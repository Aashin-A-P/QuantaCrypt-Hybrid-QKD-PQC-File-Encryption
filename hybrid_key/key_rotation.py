from dataclasses import dataclass
from typing import Optional
from qkd.qkd_simulator import generate_qkd_key
from pqc.kyber_simulator import generate_pqc_shared_secret
from .key_fusion import derive_hybrid_key_bundle


@dataclass
class RotationPolicy:
    max_qber: float = 0.05          # 5%
    max_age_seconds: Optional[int] = None  # not enforced here (caller can handle time)


def should_rotate_key(qber: float, policy: RotationPolicy) -> bool:
    """
    Decide if a new hybrid key should be generated based on QBER.
    """
    if qber > policy.max_qber:
        return True
    return False


def generate_new_hybrid_bundle() -> tuple:
    """
    End-to-end generation of:
        K_QKD, K_PQC, HybridKeyBundle
    """
    k_qkd, qber = generate_qkd_key()
    k_pqc, pk, ct = generate_pqc_shared_secret()
    bundle = derive_hybrid_key_bundle(k_qkd, k_pqc, qber=qber, length_bytes=64)
    return k_qkd, k_pqc, bundle
