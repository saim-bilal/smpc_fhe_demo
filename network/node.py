"""
SMPC party node — a simple TCP server that holds shares and runs
local finite-field arithmetic when the orchestrator tells it to.
"""

import argparse
import json
import socket
import threading

from config import FIELD_PRIME
from network.transport import recv_json


def handle_message(msg, state, party_id):
    """Process one command from the orchestrator and return a response dict."""
    cmd = msg.get("cmd", "")

    if cmd == "PING":
        return {"status": "OK"}

    elif cmd == "SET_SHARES":
        state["x_share"] = int(msg["x_share"])
        state["y_share"] = int(msg["y_share"])
        return {"status": "OK"}

    elif cmd == "RECEIVE_TRIPLE":
        state["a_share"] = int(msg["a_share"])
        state["b_share"] = int(msg["b_share"])
        state["c_share"] = int(msg["c_share"])
        return {"status": "OK"}

    elif cmd == "ADD_SHARES":
        s = (state["x_share"] + state["y_share"]) % FIELD_PRIME
        state["s_share"] = s
        return {"status": "OK", "s_share": s}

    elif cmd == "COMPUTE_D_E":
        d = (state["x_share"] - state["a_share"]) % FIELD_PRIME
        e = (state["y_share"] - state["b_share"]) % FIELD_PRIME
        state["d_share"] = d
        state["e_share"] = e
        return {"status": "OK", "d_share": d, "e_share": e}

    elif cmd == "COMPUTE_Z":
        d = int(msg["d"])
        e = int(msg["e"])
        z = state["c_share"]
        z = (z + d * state["b_share"]) % FIELD_PRIME
        z = (z + e * state["a_share"]) % FIELD_PRIME
        if party_id == 0:
            z = (z + d * e) % FIELD_PRIME
        state["z_share"] = z
        return {"status": "OK", "z_share": z}

    elif cmd == "STORE":
        state[msg["label"]] = msg["share"]
        return {"status": "OK"}

    elif cmd == "GET":
        return {"share": state.get(msg["label"], 0)}

    return {"error": f"Unknown command: {cmd}"}


def handle_connection(conn, party_id, state):
    """Read one JSON command, run it, send back the JSON reply."""
    try:
        msg = recv_json(conn)
        reply = handle_message(msg, state, party_id)
        conn.sendall(json.dumps(reply).encode())
    except Exception as exc:
        try:
            conn.sendall(json.dumps({"error": str(exc)}).encode())
        except Exception:
            pass
    finally:
        conn.close()


def run_node(host, port, party_id):
    """Start a blocking TCP server for this party."""
    state = {}
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(10)
    print(f"[Node {party_id}] Listening on {host}:{port}")

    while True:
        conn, _ = srv.accept()
        threading.Thread(
            target=handle_connection,
            args=(conn, party_id, state),
            daemon=True,
        ).start()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Start an SMPC party node")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--id",   type=int, required=True)
    args = p.parse_args()
    run_node(args.host, args.port, args.id)