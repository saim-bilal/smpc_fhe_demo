"""
Global configuration for the SMPC + FHE demo.
"""

# ── Finite-field parameters ──────────────────────────────────────────────
FIELD_PRIME: int = 2**61 - 1       # Large Mersenne prime for modular arithmetic
NUM_PARTIES: int = 7               # Default number of SMPC parties

# ── BFV Fully-Homomorphic Encryption defaults ────────────────────────────
BFV_POLY_MODULUS_DEGREE: int = 4096
BFV_PLAIN_MODULUS: int = 65537     # Products a*b must be < this value
