"""
Additive secret sharing over a finite field.

A secret *s* is split into *n* shares such that:

    s ≡ s_1 + s_2 + … + s_n   (mod p)

Any strict subset of shares reveals **nothing** about s (information-
theoretic security).  Reconstruction requires *all* n shares.
"""

import random
from typing import List

from config import FIELD_PRIME
from crypto_core.field import FieldElement, SecretShare, ShareVector, mod


def share_secret(secret: FieldElement, num_parties: int) -> ShareVector:
    """
    Split *secret* into *num_parties* additive shares.

    The first (n − 1) shares are drawn uniformly at random from Z_p.
    The last share is computed so that the shares sum to *secret* mod p.
    """
    random_shares: List[SecretShare] = [
        random.randrange(FIELD_PRIME) for _ in range(num_parties - 1)
    ]
    final_share: SecretShare = mod(secret - sum(random_shares))
    return random_shares + [final_share]


def reconstruct(shares: ShareVector) -> FieldElement:
    """
    Recover the original secret by summing all shares modulo p.
    """
    return mod(sum(shares))
