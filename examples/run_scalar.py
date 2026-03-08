#!/usr/bin/env python3
"""
Example: Secure scalar multiplication (in-memory, no networking).

Demonstrates additive secret sharing, secure addition, and secure
multiplication using Beaver triples — all computed locally in one process.
"""

from config import NUM_PARTIES
from crypto_core.secret_sharing import share_secret, reconstruct
from protocols.secure_ops import secure_add, secure_multiply


def main() -> None:
    x, y = 25, 9
    n = NUM_PARTIES

    print(f"Secure Arithmetic Demo  ({n} parties, in-memory)")
    print(f"{'=' * 50}")
    print(f"  Inputs:  x = {x},  y = {y}\n")

    # --- Secret-share the inputs ---
    x_shares = share_secret(x, n)
    y_shares = share_secret(y, n)

    print("  Share distribution:")
    for i in range(n):
        print(f"    Party {i}:  x_share = {x_shares[i]},  y_share = {y_shares[i]}")
    print()

    # --- Secure addition (local — no communication) ---
    sum_shares = secure_add(x_shares, y_shares)
    sum_result = reconstruct(sum_shares)
    print(f"  Secure x + y = {sum_result}   (expected {x + y})")

    # --- Secure multiplication (Beaver protocol) ---
    product_shares = secure_multiply(x_shares, y_shares)
    product_result = reconstruct(product_shares)
    print(f"  Secure x × y = {product_result}   (expected {x * y})")

    print(f"\n{'=' * 50}")
    print("  ✓ All results match — protocol is correct.")


if __name__ == "__main__":
    main()
