# QuantaCrypt-Hybrid-QKD-PQC-File-Encryption

🛡️ QuantaCrypt
A Multi-Layer Hybrid Encryption Model for Post-Quantum Secure File Protection

QuantaCrypt is a future-proof file encryption framework that blends the power of Quantum Key Distribution (QKD) and Post-Quantum Cryptography (PQC) with modern cryptographic engineering practices. It is designed to secure sensitive data even in the era of fully capable quantum computers.

🚀 Key Features

Hybrid QKD + PQC Key Generation
Combines quantum-grade randomness with lattice-based post-quantum security.

Shamir’s Secret Sharing-Based Key Management
Eliminates single-point compromise by splitting hybrid keys across independent channels.

Dynamic Per-Block Key Rotation
Ensures perfect forward secrecy by generating a unique key for every file block.

AES-GCM Authenticated Encryption
Provides confidentiality, integrity, and tamper detection for all encrypted files.

Defense-in-Depth Security Architecture
Multiple cryptographic layers protect against both classical and quantum adversaries.

🧩 Tech Stack

Python

AES-GCM (PyCryptodome / cryptography)

Open Quantum Safe (Kyber, Dilithium)

Shamir’s Secret Sharing

SHA3-512 / BLAKE3 hashing

CLI-based interface

🔒 Why QuantaCrypt?

Quantum computers will soon break classical cryptosystems like RSA and ECC.
QuantaCrypt ensures long-term, post-quantum secure file protection using a layered hybrid design that remains safe even if one layer is compromised.