"""
Beaver triple generation (plaintext, trusted-dealer model).

A Beaver triple ``(a, b, c)`` satisfies ``c = a * b  (mod p)``.
The three values are **secret-shared** across parties so that no single
party learns a, b, or c in the clear.  These triples power the
multiplication step of the SMPC protocol.
"""

import random
from typing import List

from config import FIELD_PRIME
from crypto_core.field import FieldElement, BeaverTriple, mul
from crypto_core.secret_sharing import share_secret


def generate_triple(num_parties: int) -> BeaverTriple:
    """
    Generate **one** Beaver triple and secret-share it among *num_parties*.

    Returns
    -------
    (a_shares, b_shares, c_shares)
        Each list has length *num_parties*.  Reconstructing all three
        lists yields ``(a, b, c)`` with ``c == a * b  (mod p)``.
    """
    a: FieldElement = random.randrange(FIELD_PRIME)
    b: FieldElement = random.randrange(FIELD_PRIME)
    c: FieldElement = mul(a, b)

    a_shares = share_secret(a, num_parties)
    b_shares = share_secret(b, num_parties)
    c_shares = share_secret(c, num_parties)

    return a_shares, b_shares, c_shares


def generate_triples(count: int, num_parties: int) -> List[BeaverTriple]:
    """Generate *count* independent Beaver triples."""
    return [generate_triple(num_parties) for _ in range(count)]
