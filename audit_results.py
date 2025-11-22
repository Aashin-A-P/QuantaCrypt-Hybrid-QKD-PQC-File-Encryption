# audit_metrics_generator.py

import os
import time
import json
import random
import matplotlib.pyplot as plt
import statistics

from audit.audit_log import (
    create_log_entry, append_log, get_last_log_hash, hash_entry
)
from audit.audit_signer import sign_log_entry, verify_log_entry
from audit.pychain_anchor import (
    compute_audit_hash, anchor_to_blockchain, verify_anchor
)

# OUTPUT FOLDERS
BASE_DIR = "audit_results"
PLOT_DIR = os.path.join(BASE_DIR, "plots")
os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

# FAKE PQC KEYS FOR METRICS
sk = os.urandom(32)
pk = os.urandom(32)

# CLEAN FILES FIRST
if os.path.exists("audit.log"):
    os.remove("audit.log")
if os.path.exists("audit_anchor.json"):
    os.remove("audit_anchor.json")


# -------------------------------------------------------------
# RUN AUDIT METRICS
# -------------------------------------------------------------
def run_audit_metrics(runs=20):
    results = {
        "runs": runs,
        "metrics": []
    }

    for i in range(runs):
        print(f"[+] Run {i+1}/{runs}")

        # -----------------------------
        # ENTRY CREATION
        # -----------------------------
        t1 = time.time()
        entry = create_log_entry("TEST_EVENT", {"value": random.randint(1, 999)})
        t2 = time.time()
        entry_create_ms = (t2 - t1) * 1000

        # Entry size
        entry_size = len(json.dumps(entry).encode())

        # -----------------------------
        # PQC SIGNATURE
        # -----------------------------
        t3 = time.time()
        signed_entry = sign_log_entry(entry, sk, pk)
        t4 = time.time()
        sig_time_ms = (t4 - t3) * 1000

        # Extract signature size
        signature_size = len(signed_entry["signature"]) // 2  # hex → bytes

        # Verification time
        t5 = time.time()
        valid = verify_log_entry(signed_entry)
        t6 = time.time()
        verify_time_ms = (t6 - t5) * 1000

        # -----------------------------
        # APPEND + HASH-CHAIN
        # -----------------------------
        t7 = time.time()
        append_log(signed_entry, sk, pk)
        t8 = time.time()
        append_time_ms = (t8 - t7) * 1000

        # Hash-chain timings
        t9 = time.time()
        last_hash = get_last_log_hash()
        t10 = time.time()
        get_hash_ms = (t10 - t9) * 1000

        # -----------------------------
        # BLOCKCHAIN ANCHOR
        # -----------------------------
        t11 = time.time()
        anchor_data = anchor_to_blockchain()
        t12 = time.time()

        anchor_time_ms = (t12 - t11) * 1000
        audit_log_hash = compute_audit_hash()

        # -----------------------------
        # TAMPER DETECTION TEST
        # -----------------------------
        tamper_result = verify_anchor()
        tamper_ok = tamper_result["status"]

        results["metrics"].append({
            "entry_creation_ms": entry_create_ms,
            "entry_size_bytes": entry_size,

            "signature_time_ms": sig_time_ms,
            "signature_size": signature_size,
            "verify_time_ms": verify_time_ms,
            "signature_valid": valid,

            "append_time_ms": append_time_ms,
            "get_last_hash_ms": get_hash_ms,

            "anchor_time_ms": anchor_time_ms,
            "audit_hash": audit_log_hash,
            "tamper_status": tamper_ok
        })

    return results


# -------------------------------------------------------------
# SAVE RESULTS JSON
# -------------------------------------------------------------
def save_json(results):
    path = os.path.join(BASE_DIR, "results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[✓] Saved audit metrics → {path}")


# -------------------------------------------------------------
# PLOT HELPER
# -------------------------------------------------------------
def plot_metric(results, key, ylabel, title, filename):
    data = [m[key] for m in results["metrics"]]
    avg = statistics.mean(data)

    plt.figure(figsize=(8,5))
    plt.plot(range(len(data)), data, marker='o')
    plt.title(f"{title} (avg={round(avg,3)} ms)")
    plt.xlabel("Run")
    plt.ylabel(ylabel)
    plt.grid(True)

    save_path = os.path.join(PLOT_DIR, filename)
    plt.savefig(save_path, dpi=200)
    plt.close()

    print(f"[+] Saved → {save_path}")


# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------
if __name__ == "__main__":
    results = run_audit_metrics(runs=20)
    save_json(results)

    plot_metric(results, "entry_creation_ms", "ms", "Log Entry Creation Time", "entry_create.png")
    plot_metric(results, "signature_time_ms", "ms", "PQC Signature Time", "signature_time.png")
    plot_metric(results, "verify_time_ms", "ms", "Signature Verification Time", "verify_time.png")
    plot_metric(results, "append_time_ms", "ms", "Log Append Time", "append_time.png")
    plot_metric(results, "anchor_time_ms", "ms", "Blockchain Anchor Time", "anchor_time.png")
    plot_metric(results, "get_last_hash_ms", "ms", "Hash-Chain Retrieval Time", "hash_chain.png")

    print("\n[✓] All audit metrics successfully generated!")
