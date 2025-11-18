import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hybrid_key.key_rotation import generate_new_hybrid_bundle, RotationPolicy, should_rotate_key
from hybrid_key.share_manager import distribute_shares, reconstruct_from_records


def main():
    print("\n=== HYBRID KEY MANAGER METRICS ===\n")

    # 1) Generate Hybrid Key
    k_qkd, k_pqc, bundle = generate_new_hybrid_bundle()
    print("[HYBRID] Bundle Info")
    print("Hybrid Key Length:", len(bundle.hybrid_key))
    print("QKD Key Length   :", len(bundle.k_qkd))
    print("PQC Key Length   :", len(bundle.k_pqc))
    print("QBER             :", f"{(bundle.qber or 0)*100:.2f}%")
    print("Created At       :", bundle.created_at)
    print()

    # 2) Decide if rotation needed based on QBER
    policy = RotationPolicy(max_qber=0.05)
    rotate = should_rotate_key(bundle.qber or 0.0, policy)
    print("[ROTATION] Should Rotate:", rotate)
    print()

    # 3) Secret Sharing (e.g., 3-of-5)
    n, k = 5, 3
    records = distribute_shares(bundle.hybrid_key, n=n, k=k)
    print(f"[SHARES] Generated {len(records)} shares (k={k}, n={n})")
    for r in records:
        print(f"  Share {r.index}: x={r.x}, channel={r.channel}, len={len(r.data)} bytes")
    print()

    # 4) Reconstruction from first k shares
    reconstructed = reconstruct_from_records(records, k=k, out_length=len(bundle.hybrid_key))
    print("[RECONSTRUCT] Hybrid key match:",
          reconstructed == bundle.hybrid_key)
    print("Reconstructed Length:", len(reconstructed))


if __name__ == "__main__":
    main()
