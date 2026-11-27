"""Shared pytest fixtures for end-to-end tests (Member B, Week 3).

server      -> a real rft.server.Server in a background thread (port chosen by the OS)
make_proxy  -> starts testbed/impair_proxy.py's Proxy in front of that server
run_client  -> runs the REAL client (python -m rft.client) as a subprocess
make_file   -> writes a random test file and returns (path, sha256 hex)

Both members can use these in their own tests.
"""
import hashlib
import os
import re
import subprocess
import sys
import threading

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "testbed"))

from impair_proxy import Impairment, Proxy  # noqa: E402
from rft.server import Server  # noqa: E402


@pytest.fixture
def server(tmp_path):
    srv = Server("127.0.0.1", 0, str(tmp_path / "received"), linger=0.5, inactivity=30.0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.stop()
    t.join(3)


@pytest.fixture
def make_proxy(server):
    made = []

    def factory(outage=None, seed=1, **impairments):
        proxy = Proxy(("127.0.0.1", 0), server.address,
                      Impairment(seed=seed, outage=outage, **impairments),
                      Impairment(seed=seed + 1, outage=outage, **impairments))
        t = threading.Thread(target=proxy.serve_forever, daemon=True)
        t.start()
        made.append((proxy, t))
        return proxy

    yield factory
    for proxy, t in made:
        proxy.stop()
        t.join(3)


@pytest.fixture
def make_file(tmp_path):
    def factory(size, name="src.bin"):
        data = os.urandom(size)
        path = tmp_path / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()
    return factory


@pytest.fixture
def run_client(tmp_path):
    def run(path, port, window=1, timeout=180, extra=()):
        log = tmp_path / f"client_{os.path.basename(str(path))}.csv"
        cmd = [sys.executable, "-m", "rft.client", str(path), "--host", "127.0.0.1",
               "--port", str(port), "--window", str(window), "--log", str(log), *extra]
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return run


def summary(stdout):
    """Pull the final numbers out of the client's printed summary."""
    def num(pattern):
        m = re.search(pattern, stdout)
        return float(m.group(1)) if m else None
    return {
        "ok": "Verification: OK" in stdout,
        "seconds": num(r"Completion time: ([\d.]+) seconds"),
        "mbps": num(r"Goodput: ([\d.]+) Mbps\s*\nDATA"),
        "retransmissions": num(r"DATA retransmissions: (\d+)\s*\nRetransmission ratio"),
        "ratio_pct": num(r"Retransmission ratio: ([\d.]+)%"),
    }


def sha_of(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()
