"""
Secure matrix multiplication using batched Beaver triples. Along with addition.

Each element ``C[i][j] = Σ_k  A[i][k] · B[k][j]`` requires one secure
scalar multiplication (and hence one Beaver triple).  Triples are
pre-generated in a batch and consumed sequentially.
"""

from typing import List

from config import FIELD_PRIME
from crypto_core.field import FieldElement, BeaverTriple
from crypto_core.secret_sharing import share_secret, reconstruct
from protocols.secure_ops import secure_add, secure_multiply

Matrix = List[List[FieldElement]]


def count_multiplications(rows_a: int, cols_a: int, cols_b: int) -> int:
    """Return the number of scalar multiplies needed for an (m×k) × (k×n) product."""
    return rows_a * cols_a * cols_b


def secure_matrix_multiply(
    A: Matrix,
    B: Matrix,
    num_parties: int,
    triples: List[BeaverTriple],
) -> Matrix:
    """
    Compute ``C = A × B`` element-wise using secure scalar multiplications.

    Parameters
    ----------
    A : Matrix
        Left matrix  (rows_a × cols_a).
    B : Matrix
        Right matrix (cols_a × cols_b).
    num_parties : int
        Number of SMPC parties.
    triples : list[BeaverTriple]
        Pre-generated Beaver triples — one per scalar multiply
        (i.e. ``rows_a * cols_a * cols_b`` triples).

    Returns
    -------
    Matrix
        The product matrix C (rows_a × cols_b).
    """
    rows_a = len(A)
    cols_a = len(A[0])
    cols_b = len(B[0])

    C: Matrix = [[0] * cols_b for _ in range(rows_a)]
    triple_idx = 0

    for i in range(rows_a):
        for j in range(cols_b):
            accumulator = 0
            for k in range(cols_a):
                x_shares = share_secret(A[i][k], num_parties)
                y_shares = share_secret(B[k][j], num_parties)

                product_shares = secure_multiply(
                    x_shares, y_shares, triple=triples[triple_idx]
                )
                product = reconstruct(product_shares)
                triple_idx += 1

                accumulator = (accumulator + product) % FIELD_PRIME
            C[i][j] = accumulator

    return C


def secure_matrix_add(
    A: Matrix,
    B: Matrix,
    num_parties: int,
) -> Matrix:
    """
    Compute ``C = A + B`` element-wise using secure addition.

    Addition is purely local — no Beaver triples or communication are needed.
    Each element pair is secret-shared, the shares are added locally,
    and the result is reconstructed.
    """
    rows = len(A)
    cols = len(A[0])
    C: Matrix = [[0] * cols for _ in range(rows)]

    for i in range(rows):
        for j in range(cols):
            a_shares = share_secret(A[i][j], num_parties)
            b_shares = share_secret(B[i][j], num_parties)
            sum_shares = secure_add(a_shares, b_shares)
            C[i][j] = reconstruct(sum_shares)

    return C
