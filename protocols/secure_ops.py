"""
Local (in-memory) secure arithmetic using Beaver's multiplication protocol.

These functions operate directly on share vectors — no networking is
involved.  For the distributed, TCP-node version see
``network.orchestrator``.

Protocol sketch (secure multiply of secret-shared *x* and *y*):

1. Obtain a Beaver triple ``(a, b, c)`` with ``c = a·b``.
2. Each party *i* computes  ``d_i = x_i − a_i``  and  ``e_i = y_i − b_i``.
3. All parties open (reconstruct) *d* and *e*.
   These are uniformly random masks — revealing them leaks nothing.
4. Each party *i* computes its output share:
       ``z_i = c_i + d·b_i + e·a_i``   (party 0 also adds ``d·e``).
5. The shares ``z_i`` reconstruct to ``x·y  (mod p)``.
"""

from typing import Optional

from crypto_core.field import (
    FieldElement,
    ShareVector,
    BeaverTriple,
    add,
    sub,
    mul,
)
from crypto_core.secret_sharing import reconstruct
from crypto_core.beaver import generate_triple


def secure_add(x_shares: ShareVector, y_shares: ShareVector) -> ShareVector:
    """
    Add two secret-shared values **locally** (no communication needed).

    Each party simply adds its own pair of shares.
    """
    return [add(x, y) for x, y in zip(x_shares, y_shares)]


def secure_multiply(
    x_shares: ShareVector,
    y_shares: ShareVector,
    triple: Optional[BeaverTriple] = None,
    use_fhe: bool = False,
) -> ShareVector:
    """
    Multiply two secret-shared values via the Beaver triple protocol.

    Parameters
    ----------
    x_shares, y_shares : ShareVector
        Additive shares of the two factors.
    triple : BeaverTriple, optional
        A pre-generated ``(a_shares, b_shares, c_shares)`` triple.
        If *None*, a fresh triple is generated on the fly.
    use_fhe : bool
        When *triple* is None and this flag is True, the triple is
        generated using FHE (BFV) rather than the plaintext trusted dealer.
    """
    num_parties = len(x_shares)

    # --- Step 1: obtain Beaver triple ---
    if triple is not None:
        a_shares, b_shares, c_shares = triple
    elif use_fhe:
        from crypto_core.fhe import generate_triple_fhe
        a_shares, b_shares, c_shares = generate_triple_fhe(num_parties)
    else:
        a_shares, b_shares, c_shares = generate_triple(num_parties)

    # --- Step 2: compute masked differences ---
    d_shares = [sub(x, a) for x, a in zip(x_shares, a_shares)]
    e_shares = [sub(y, b) for y, b in zip(y_shares, b_shares)]

    # --- Step 3: open d and e (safe — they are random masks) ---
    d: FieldElement = reconstruct(d_shares)
    e: FieldElement = reconstruct(e_shares)

    # --- Step 4: each party computes its output share ---
    result_shares: ShareVector = []
    for i in range(num_parties):
        z_i = add(
            add(c_shares[i], mul(d, b_shares[i])),
            add(mul(e, a_shares[i]), mul(d, e) if i == 0 else 0),
        )
        result_shares.append(z_i)

    return result_shares
