import hashlib
from dataclasses import dataclass
from datetime import datetime


@dataclass
class HybridKeyBundle:
    hybrid_key: bytes
    k_qkd: bytes
    k_pqc: bytes
    qber: float | None
    created_at: str
    info: dict


def derive_hybrid_key(k_qkd: bytes, k_pqc: bytes, length_bytes: int = 64) -> bytes:
    if not isinstance(k_qkd, (bytes, bytearray)) or not isinstance(k_pqc, (bytes, bytearray)):
        raise TypeError("k_qkd and k_pqc must be bytes-like")
    digest = hashlib.sha3_512(k_qkd + k_pqc).digest()
    return digest[:length_bytes]


def derive_hybrid_key_bundle(
    k_qkd: bytes,
    k_pqc: bytes,
    qber: float | None = None,
    length_bytes: int = 64,
    scheme_label: str = "QKD+SimKyber512"
) -> HybridKeyBundle:
    hk = derive_hybrid_key(k_qkd, k_pqc, length_bytes=length_bytes)
    bundle = HybridKeyBundle(
        hybrid_key=hk,
        k_qkd=k_qkd,
        k_pqc=k_pqc,
        qber=qber,
        created_at=datetime.utcnow().isoformat(timespec="seconds") + "Z",
        info={
            "hybrid_length_bytes": length_bytes,
            "qkd_key_bytes": len(k_qkd),
            "pqc_key_bytes": len(k_pqc),
            "fusion_hash": "SHA3-512",
            "scheme": scheme_label,
        },
    )
    return bundle
