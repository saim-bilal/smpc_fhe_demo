"""
Modular arithmetic over a finite field Z_p.

All SMPC computations happen in this field. The prime p is configured
in ``config.FIELD_PRIME`` (default: the Mersenne prime 2^61 − 1).
"""

from typing import List, Tuple

from config import FIELD_PRIME

# ---------------------------------------------------------------------------
# Type aliases — make data flow self-documenting
# ---------------------------------------------------------------------------
FieldElement = int
"""An element of Z_p (conceptually; at runtime just an ``int``)."""

SecretShare = int
"""A single party's additive share of a secret."""

ShareVector = List[SecretShare]
"""One share per party — together they reconstruct a secret."""

BeaverTriple = Tuple[ShareVector, ShareVector, ShareVector]
"""(a_shares, b_shares, c_shares) where c = a * b  (mod p)."""


# ---------------------------------------------------------------------------
# Field operations
# ---------------------------------------------------------------------------

def mod(value: int) -> FieldElement:
    """Reduce *value* modulo FIELD_PRIME into [0, p)."""
    return value % FIELD_PRIME


def add(x: FieldElement, y: FieldElement) -> FieldElement:
    """Addition in Z_p."""
    return (x + y) % FIELD_PRIME


def sub(x: FieldElement, y: FieldElement) -> FieldElement:
    """Subtraction in Z_p."""
    return (x - y) % FIELD_PRIME


def mul(x: FieldElement, y: FieldElement) -> FieldElement:
    """Multiplication in Z_p."""
    return (x * y) % FIELD_PRIME
