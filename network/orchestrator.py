#!/usr/bin/env python3
"""
SMPC Orchestrator — spawns 5 party nodes, distributes shares,
and drives secure addition / multiplication over TCP.
"""

import argparse
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_SMPC_ROOT = os.path.dirname(_HERE)
if _SMPC_ROOT not in sys.path:
    sys.path.insert(0, _SMPC_ROOT)

from config import NUM_PARTIES, FIELD_PRIME
from crypto_core.secret_sharing import share_secret, reconstruct
from crypto_core.beaver import generate_triple
from network.transport import send_command, HOST, BASE_PORT

try:
    from crypto_core.fhe import generate_triple_fhe
except Exception:
    generate_triple_fhe = None


# ── helpers ───────────────────────────────────────────────────────────────

def _send_to_all(num_parties, base_port, make_msg):
    """Send a per-party message to every node.  *make_msg(i)* returns the dict."""
    for i in range(num_parties):
        send_command(base_port + i, make_msg(i))


def _collect(num_parties, base_port, msg):
    """Send the same command to every node and collect the responses."""
    return [send_command(base_port + i, msg) for i in range(num_parties)]


def _make_triple(num_parties, use_fhe=False):
    if use_fhe:
        if generate_triple_fhe is None:
            raise RuntimeError("FHE triple generator not available — install pyfhel.")
        return generate_triple_fhe(num_parties)
    return generate_triple(num_parties)


# ── process management ────────────────────────────────────────────────────

def start_nodes(num_parties, base_port):
    """Spawn *num_parties* node sub-processes and wait until they all respond."""
    procs = []
    for i in range(num_parties):
        port = base_port + i
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "network.node",
             "--host", HOST, "--port", str(port), "--id", str(i)],
            cwd=_SMPC_ROOT,
        ))
        time.sleep(0.25)

    # wait for each node to answer a PING
    for i in range(num_parties):
        port = base_port + i
        for attempt in range(20):
            try:
                if send_command(port, {"cmd": "PING"}, timeout=2.0).get("status") == "OK":
                    print(f"[Node {i}] Ready on port {port}")
                    break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError(f"Node {i} on port {port} never became ready.")
    return procs


# ── secure addition (scalar) ─────────────────────────────────────────────

def secure_add_networked(x, y, num_parties, base_port):
    x_shares = share_secret(x, num_parties)
    y_shares = share_secret(y, num_parties)

    _send_to_all(num_parties, base_port, lambda i: {
        "cmd": "SET_SHARES",
        "x_share": x_shares[i], "y_share": y_shares[i],
    })

    resps = _collect(num_parties, base_port, {"cmd": "ADD_SHARES"})
    return reconstruct([int(r["s_share"]) for r in resps])


# ── secure addition (matrix) ─────────────────────────────────────────────

def secure_matrix_add_networked(A, B, num_parties, base_port):
    rows, cols = len(A), len(A[0])
    return [
        [secure_add_networked(A[i][j], B[i][j], num_parties, base_port)
         for j in range(cols)]
        for i in range(rows)
    ]


# ── secure multiplication (scalar) ───────────────────────────────────────

def secure_multiply_networked(x, y, num_parties, base_port, use_fhe=False):
    x_shares = share_secret(x, num_parties)
    y_shares = share_secret(y, num_parties)

    # 1. distribute input shares
    _send_to_all(num_parties, base_port, lambda i: {
        "cmd": "SET_SHARES",
        "x_share": x_shares[i], "y_share": y_shares[i],
    })

    # 2. generate & distribute Beaver triple
    a_sh, b_sh, c_sh = _make_triple(num_parties, use_fhe)
    _send_to_all(num_parties, base_port, lambda i: {
        "cmd": "RECEIVE_TRIPLE",
        "a_share": a_sh[i], "b_share": b_sh[i], "c_share": c_sh[i],
    })

    # 3. collect masked differences
    resps = _collect(num_parties, base_port, {"cmd": "COMPUTE_D_E"})
    d = sum(int(r["d_share"]) for r in resps) % FIELD_PRIME
    e = sum(int(r["e_share"]) for r in resps) % FIELD_PRIME

    # 4. compute output shares
    resps = _collect(num_parties, base_port, {"cmd": "COMPUTE_Z", "d": d, "e": e})
    return reconstruct([int(r["z_share"]) for r in resps])


# ── multiply with a pre-supplied triple ───────────────────────────────────

def _multiply_with_triple(x, y, a_sh, b_sh, c_sh, num_parties, base_port):
    x_shares = share_secret(x, num_parties)
    y_shares = share_secret(y, num_parties)

    _send_to_all(num_parties, base_port, lambda i: {
        "cmd": "SET_SHARES",
        "x_share": x_shares[i], "y_share": y_shares[i],
    })
    _send_to_all(num_parties, base_port, lambda i: {
        "cmd": "RECEIVE_TRIPLE",
        "a_share": a_sh[i], "b_share": b_sh[i], "c_share": c_sh[i],
    })

    resps = _collect(num_parties, base_port, {"cmd": "COMPUTE_D_E"})
    d = sum(int(r["d_share"]) for r in resps) % FIELD_PRIME
    e = sum(int(r["e_share"]) for r in resps) % FIELD_PRIME

    resps = _collect(num_parties, base_port, {"cmd": "COMPUTE_Z", "d": d, "e": e})
    time.sleep(0.01)
    return reconstruct([int(r["z_share"]) for r in resps])


# ── secure multiplication (matrix, batched triples) ──────────────────────

def secure_matrix_multiply_networked(A, B, num_parties, base_port, use_fhe=False):
    rows_a, cols_a, cols_b = len(A), len(A[0]), len(B[0])
    triples = [_make_triple(num_parties, use_fhe)
               for _ in range(rows_a * cols_a * cols_b)]

    C = [[0] * cols_b for _ in range(rows_a)]
    idx = 0
    for i in range(rows_a):
        for j in range(cols_b):
            acc = 0
            for k in range(cols_a):
                a_sh, b_sh, c_sh = triples[idx]; idx += 1
                acc = (acc + _multiply_with_triple(
                    A[i][k], B[k][j], a_sh, b_sh, c_sh,
                    num_parties, base_port)) % FIELD_PRIME
            C[i][j] = acc
    return C


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="SMPC Orchestrator")
    ap.add_argument("--spawn",     action="store_true", help="Spawn node sub-processes")
    ap.add_argument("--scalar",    action="store_true", help="Run scalar demo")
    ap.add_argument("--matrix",    action="store_true", help="Run matrix demo")
    ap.add_argument("--x",         type=int, default=12)
    ap.add_argument("--y",         type=int, default=7)
    ap.add_argument("--use-fhe",   action="store_true")
    ap.add_argument("--base-port", type=int, default=BASE_PORT)
    args = ap.parse_args()

    n = NUM_PARTIES
    bp = args.base_port
    procs = start_nodes(n, bp) if args.spawn else []

    try:
        if args.scalar:
            s = secure_add_networked(args.x, args.y, n, bp)
            p = secure_multiply_networked(args.x, args.y, n, bp, args.use_fhe)
            print(f"\n{'#' * 50}")
            print(f"  Operands:  x = {args.x},  y = {args.y}")
            print(f"  Secure x + y = {s}   (expected {args.x + args.y})")
            print(f"  Secure x * y = {p}   (expected {args.x * args.y})")
            print(f"{'#' * 50}\n")

        elif args.matrix:
            A = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
            B = [[9, 8, 7], [6, 5, 4], [3, 2, 1]]
            print(f"\n{'#' * 50}")
            print(f"  Matrix A : {A}")
            print(f"  Matrix B : {B}")
            S = secure_matrix_add_networked(A, B, n, bp)
            C = secure_matrix_multiply_networked(A, B, n, bp, args.use_fhe)
            print(f"  Secure A + B = {S}")
            print(f"  Secure A * B = {C}")
            print(f"{'#' * 50}")

        else:
            print("Specify --scalar or --matrix")
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(0.2)


if __name__ == "__main__":
    main()