import streamlit as st
import os
import sys
import base64

# Add PATHS
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import project modules
from utils.io_utils import read_file_bytes, write_file_bytes
from utils.hashing import sha3_512

# KEY EXCHANGE
from key_exchange.qkd_simulator import run_qkd_key_exchange
from key_exchange.pqc_kyber import generate_pqc_shared_secret
from key_exchange.hybrid_key_derivation import derive_hybrid_key

# CRYPTO
from crypto_core.file_encryptor import encrypt_file_bytes
from crypto_core.file_packager import package_encrypted_file
from crypto_core.file_decryptor import decrypt_packed_file

# SIGNATURES
from pqc_signature.dilithium_sign import generate_sig_keypair, sign_file_bytes
from pqc_signature.dilithium_verify import verify_file_signature

# AUDIT
from audit.audit_log import create_log_entry, append_log
from audit.audit_signer import sign_log_entry


# =========================================================
# STREAMLIT PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="QuantaCrypt Hybrid Quantum-Safe Encryption",
    layout="wide",
    page_icon="🔐",
)


st.title("🔐 QuantaCrypt — Hybrid QKD + PQC Quantum-Safe Encryption System")
st.markdown("---")


# =========================================================
# SESSION STATE (to persist encrypted results)
# =========================================================
if "encrypted" not in st.session_state:
    st.session_state.encrypted = False
    st.session_state.data = {}


# =========================================================
# ENCRYPTION WORKFLOW (STREAMLIT)
# =========================================================
if st.sidebar.button("Encryption Page"):
    st.session_state.page = "encrypt"

if st.sidebar.button("Decryption Page"):
    st.session_state.page = "decrypt"

if st.sidebar.button("Audit Log"):
    st.session_state.page = "audit"


if "page" not in st.session_state:
    st.session_state.page = "encrypt"



# =========================================================
# PAGE: ENCRYPTION
# =========================================================
if st.session_state.page == "encrypt":
    st.header("🔏 Encrypt & Sign File")

    uploaded = st.file_uploader("Upload File to Encrypt", type=None)

    col1, col2 = st.columns(2)
    eve_attack = col1.checkbox("Simulate Eve Attack on QKD (High QBER)")
    pqc_attack = col2.checkbox("Simulate PQC Compromise (Kyber broken)")

    if uploaded and st.button("🔒 Encrypt File"):

        plaintext = uploaded.read()
        file_size = len(plaintext)

        st.info(f"File size: **{file_size} bytes**")

        # ============================
        # QKD
        # ============================
        qkd_key, qber, compromised_qkd = run_qkd_key_exchange(eve=eve_attack)

        st.subheader("🔹 QKD Results")
        st.write(f"QBER: **{qber:.4f}**")
        st.write(f"Channel Compromised: **{compromised_qkd}**")

        # ============================
        # PQC KEM (Kyber)
        # ============================
        pqc_key, pk_kem, ct_kem = generate_pqc_shared_secret()

        compromised_pqc = pqc_attack   # simulate PQC break

        st.subheader("🔹 PQC (Kyber) Results")
        st.write(f"PQC Compromised: **{compromised_pqc}**")

        # If PQC compromised → treat as insecure
        if compromised_pqc:
            pqc_key = b"\x00" * 32   # corrupted secret

        # ============================
        # HYBRID KEY
        # ============================
        hybrid_key = derive_hybrid_key(qkd_key, pqc_key)

        st.subheader("🔑 Hybrid Key (QKD ⊕ PQC)")
        st.code(sha3_512(hybrid_key).hex()[:64] + "...")

        # BLOCK ENCRYPTION IF ANY COMPROMISE
        if compromised_qkd or compromised_pqc:
            st.error("❌ Encryption aborted — one or more channels were compromised.")
        else:
            ciphertext, nonce, tag = encrypt_file_bytes(hybrid_key, plaintext)
            packaged = package_encrypted_file(ciphertext, nonce, tag, file_size)

            # SIGNATURE
            pk_sig, sk_sig = generate_sig_keypair()
            signature = sign_file_bytes(packaged, sk_sig)

            # Save into session_state
            st.session_state.encrypted = True
            st.session_state.data = {
                "packaged": packaged,
                "signature": signature,
                "pk_sig": pk_sig,
                "sk_sig": sk_sig,
                "hybrid_key": hybrid_key,
                "file_name": uploaded.name,
                "compromised_qkd": compromised_qkd,
                "compromised_pqc": compromised_pqc,
                "qber": qber,
            }

            st.success("✅ Encryption successful. Ready for download & decryption.")

            # Allow download
            st.download_button(
                label="⬇ Download Encrypted File",
                data=packaged,
                file_name="cipher_package.bin",
            )

            st.download_button(
                label="⬇ Download Signature",
                data=signature,
                file_name="cipher_signature.bin",
            )


# =========================================================
# PAGE: DECRYPTION
# =========================================================
elif st.session_state.page == "decrypt":
    st.header("🔓 Decrypt File")

    if not st.session_state.encrypted:
        st.warning("⚠ No encrypted file available. Please encrypt first.")
    else:
        data = st.session_state.data

        st.subheader("🔍 Safety Checks")

        st.write(f"**QKD Compromised:** {data['compromised_qkd']}")
        st.write(f"**PQC Compromised:** {data['compromised_pqc']}")
        st.write(f"**QBER:** {data['qber']:.4f}")

        # Signature verification
        st.write("**Verifying Signature...**")
        sig_valid = verify_file_signature(
            data["packaged"], data["signature"], data["pk_sig"]
        )
        st.write(f"Signature Valid: **{sig_valid}**")

        decrypt_allowed = (
            sig_valid
            and not data["compromised_qkd"]
            and not data["compromised_pqc"]
        )

        if not decrypt_allowed:
            st.error("❌ Decryption blocked: channel/signature compromised.")
        else:
            plaintext = decrypt_packed_file(
                data["hybrid_key"], data["packaged"]
            )

            st.success("✅ File decrypted successfully!")

            st.download_button(
                "⬇ Download Decrypted File",
                data=plaintext,
                file_name=f"DECRYPTED_{data['file_name']}",
            )


# =========================================================
# PAGE: AUDIT LOG
# =========================================================
elif st.session_state.page == "audit":
    st.header("📘 Audit Log")

    if os.path.exists("audit.log"):
        st.code(open("audit.log").read())
    else:
        st.info("No audit log available yet.")
