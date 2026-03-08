"""
Fully Homomorphic Encryption (BFV scheme) via Pyfhel.

This module provides two capabilities:

1. **BFV engine helpers** — context creation, encryption, decryption, and
   homomorphic multiplication for exact integer arithmetic.
2. **FHE-based Beaver triple generation** — the product ``c = a * b`` is
   computed *homomorphically*, so no party ever sees both plaintext
   factors simultaneously.

.. note::

   The BFV plaintext modulus *t* (default 65537) bounds the maximum
   product ``a * b``.  For the demo the random factors are capped at
   ``a_max`` / ``b_max`` = 200 so that 200 × 200 = 40 000 < 65 537.
"""

import random
from typing import List

from Pyfhel import Pyfhel, PyCtxt

from config import FIELD_PRIME, BFV_POLY_MODULUS_DEGREE, BFV_PLAIN_MODULUS
from crypto_core.field import BeaverTriple
from crypto_core.secret_sharing import share_secret

# ── BFV Engine ────────────────────────────────────────────────────────────


def create_bfv_context(
    poly_modulus_degree: int = BFV_POLY_MODULUS_DEGREE,
    plain_modulus: int = BFV_PLAIN_MODULUS,
) -> Pyfhel:
    """
    Initialise and return a Pyfhel BFV context with freshly generated keys.

    Parameters
    ----------
    poly_modulus_degree : int
        Ring dimension (typically 4096 or 8192).
    plain_modulus : int
        Plaintext modulus *t*.  All plaintext arithmetic is mod *t*,
        so any product ``a * b`` must satisfy ``a * b < t``.
    """
    he = Pyfhel()
    he.contextGen(scheme="BFV", n=poly_modulus_degree, t=plain_modulus)
    he.keyGen()
    return he


def encrypt_int(he: Pyfhel, value: int) -> PyCtxt:
    """Encrypt a single integer under BFV."""
    return he.encrypt(int(value))


def decrypt_int(he: Pyfhel, ciphertext: PyCtxt) -> int:
    """Decrypt a BFV ciphertext and return the integer result."""
    plaintext = he.decrypt(ciphertext)
    return int(plaintext[0])


def multiply_ciphertexts(he: Pyfhel, ct_a: PyCtxt, ct_b: PyCtxt) -> PyCtxt:
    """Homomorphically multiply two BFV ciphertexts."""
    return ct_a * ct_b


# ── FHE-based Beaver Triple Generation ───────────────────────────────────


def generate_triple_fhe(
    num_parties: int,
    a_max: int = 200,
    b_max: int = 200,
) -> BeaverTriple:
    """
    Generate a Beaver triple where the product is computed via BFV FHE.

    Parameters
    ----------
    num_parties : int
        Number of SMPC parties to share the triple among.
    a_max, b_max : int
        Upper bounds for the random factors.  Must satisfy
        ``a_max * b_max < BFV_PLAIN_MODULUS`` to avoid overflow.
    """
    he = create_bfv_context()

    a = random.randrange(a_max)
    b = random.randrange(b_max)

    encrypted_a = encrypt_int(he, a)
    encrypted_b = encrypt_int(he, b)
    encrypted_product = multiply_ciphertexts(he, encrypted_a, encrypted_b)

    c = decrypt_int(he, encrypted_product) % FIELD_PRIME

    a_shares = share_secret(a % FIELD_PRIME, num_parties)
    b_shares = share_secret(b % FIELD_PRIME, num_parties)
    c_shares = share_secret(c, num_parties)

    return a_shares, b_shares, c_shares


def generate_triples_fhe(
    count: int,
    num_parties: int,
    a_max: int = 200,
    b_max: int = 200,
) -> List[BeaverTriple]:
    """Generate *count* FHE-based Beaver triples."""
    return [
        generate_triple_fhe(num_parties, a_max, b_max) for _ in range(count)
    ]
