"""Simple JSON-over-TCP helpers for SMPC node communication."""

import json
import socket

HOST = "127.0.0.1"
BASE_PORT = 12000
BUF = 65536


def send_command(port, payload, host=HOST, timeout=5.0):
    """Connect to a node, send a JSON command, return the JSON reply."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(json.dumps(payload).encode())
        return json.loads(sock.recv(BUF).decode())


def recv_json(conn):
    """Read one JSON message from an accepted connection."""
    return json.loads(conn.recv(BUF).decode())
