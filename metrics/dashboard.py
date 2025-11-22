# master_dashboard.py
import streamlit as st
import os
import json
from pathlib import Path
import base64

# -------------------------------------------------------------------
# Helper: Load JSON safely
# -------------------------------------------------------------------
def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None

# -------------------------------------------------------------------
# Helper: Display all PNG plots in a folder
# -------------------------------------------------------------------
def show_plots(title, folder):
    st.subheader(title)
    if not os.path.exists(folder):
        st.warning("No plots found in this module.")
        return
    
    images = [f for f in os.listdir(folder) if f.endswith(".png")]
    
    if not images:
        st.warning("No plot images found.")
        return

    for img in images:
        st.image(os.path.join(folder, img), caption=img, use_column_width=True)


# -------------------------------------------------------------------
# Streamlit App Layout
# -------------------------------------------------------------------
st.set_page_config(page_title="QuantaCrypt Evaluation Dashboard", layout="wide")

st.title("🔐 **QuantaCrypt – Full System Evaluation Dashboard**")
st.markdown("A unified performance analysis of **QKD, Kyber KEM, AES-GCM, PQC Signatures, and Audit Blockchain Anchoring**.")

# Tabs for each module
tabs = st.tabs([
    "QKD Metrics",
    "Kyber PQC Metrics",
    "AES-GCM Crypto Metrics",
    "PQC Signature Metrics",
    "Audit Log Metrics",
    "Combined Summary"
])

# -------------------------------------------------------------------
# QKD METRICS TAB
# -------------------------------------------------------------------
with tabs[0]:
    st.header("QKD Metrics (BB84 Simulation)")
    qkd_json = load_json("qkd_metrics/results.json")

    if qkd_json:
        st.json(qkd_json)
        show_plots("QKD Performance Plots", "qkd_metrics/plots")
    else:
        st.error("QKD results.json not found.")


# -------------------------------------------------------------------
# KYBER METRICS TAB
# -------------------------------------------------------------------
with tabs[1]:
    st.header("Kyber (PQC) KEM Metrics")
    kyber_json = load_json("kyber_results/results.json")

    if kyber_json:
        st.json(kyber_json)
        show_plots("Kyber KEM Plots", "kyber_results/plots")
    else:
        st.error("Kyber results.json not found.")


# -------------------------------------------------------------------
# AES-GCM METRICS TAB
# -------------------------------------------------------------------
with tabs[2]:
    st.header("AES-GCM Encryption/Decryption Metrics")
    crypto_json = load_json("crypto_results/results.json")

    if crypto_json:
        st.json(crypto_json)
        show_plots("AES-GCM Crypto Plots", "crypto_results/plots")
    else:
        st.error("Crypto results.json not found.")


# -------------------------------------------------------------------
# PQC SIGNATURE METRICS TAB
# -------------------------------------------------------------------
with tabs[3]:
    st.header("Dilithium-Inspired PQC Signature Metrics")
    sig_json = load_json("dilithium_results/results.json")

    if sig_json:
        st.json(sig_json)
        show_plots("Signature Performance Plots", "dilithium_results/plots")
    else:
        st.error("Signature results.json not found.")


# -------------------------------------------------------------------
# AUDIT LOG METRICS TAB
# -------------------------------------------------------------------
with tabs[4]:
    st.header("Audit Log + Blockchain Anchor Metrics")
    audit_json = load_json("audit_results/results.json")

    if audit_json:
        st.json(audit_json)
        show_plots("Audit Log & Blockchain Plots", "audit_results/plots")
    else:
        st.error("Audit results.json not found.")


# -------------------------------------------------------------------
# COMBINED SUMMARY DASHBOARD
# -------------------------------------------------------------------
with tabs[5]:
    st.header("📊 Combined System Overview")

    st.markdown("""
    This section shows a **high-level comparison** across all modules.
    Each module contributes to the full hybrid security pipeline:
    
    - **QKD** → Quantum entropy source  
    - **Kyber PQC** → Lattice-KEM shared secret  
    - **Hybrid SHA3 Key** → AES-256 encryption  
    - **PQC Signatures** → File authenticity  
    - **Audit Chain + Blockchain** → Tamper-evident logs  
    """)

    st.markdown("### 🔒 Security Flow Diagram")
    st.image("Final Crypto Idea.png", caption="Full Cryptographic Pipeline")

    st.markdown("### 📂 Browse individual modules from the tabs above.")



st.success("Dashboard loaded successfully!")
