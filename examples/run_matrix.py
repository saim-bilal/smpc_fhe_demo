"""
Example: Secure matrix addition and multiplication (in-memory, no networking).

Pre-generates all Beaver triples needed for multiplication, then computes
both C = A + B and C = A × B using only secret-shared arithmetic.
"""

from config import NUM_PARTIES
from crypto_core.beaver import generate_triples
from protocols.matrix_arithmetic import (
    secure_matrix_add,
    secure_matrix_multiply,
    count_multiplications,
)


def main() -> None:
    A = [[1, 2], [3, 4]]
    B = [[5, 6], [7, 8]]

    n = NUM_PARTIES
    rows_a, cols_a, cols_b = len(A), len(A[0]), len(B[0])
    num_mults = count_multiplications(rows_a, cols_a, cols_b)

    print(f"Secure Matrix Arithmetic Demo  ({n} parties, in-memory)")
    print(f"{'=' * 50}")
    print(f"  A = {A}")
    print(f"  B = {B}\n")

    # --- Secure addition (no triples needed) ---
    S = secure_matrix_add(A, B, n)
    print(f"  Secure A + B = {S}")
    print(f"  Expected     = [[6, 8], [10, 12]]")

    # --- Secure multiplication (Beaver triples) ---
    print(f"\n  Scalar multiplications required: {num_mults}")
    triples = generate_triples(num_mults, n)
    C = secure_matrix_multiply(A, B, n, triples)
    print(f"  Secure A × B = {C}")
    print(f"  Expected     = [[19, 22], [43, 50]]")

    print(f"\n{'=' * 50}")


if __name__ == "__main__":
    main()

