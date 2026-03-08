"""
Secure Multi-Party Computation + Fully Homomorphic Encryption demo.

Quick-start (in-memory, no networking, run from inside the directory)::

    from crypto_core.secret_sharing import share_secret, reconstruct
    from protocols.secure_ops import secure_add, secure_multiply

    x_shares = share_secret(25, 5)
    y_shares = share_secret(9, 5)
    product  = reconstruct(secure_multiply(x_shares, y_shares))
    # product == 225
"""
