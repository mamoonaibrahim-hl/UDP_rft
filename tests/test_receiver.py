"""Tests for rft/server.py (Member B, Week 2). Run: python -m pytest tests -v"""
import hashlib
import os
import socket
import struct
import threading
import time

import pytest

from rft import packet as P
from rft.server import (STATUS_HASH_MISMATCH, STATUS_OK, Server, parse_syn_payload,
                        safe_name)


def syn_payload(data: bytes, name="f.bin", chunk=1024, sha=None):
    sha = sha if sha is not None else hashlib.sha256(data).digest()
    n = name.encode()
    return struct.pack("!QH32sH", len(data), chunk, sha, len(n)) + n


class Client:
    """Bare-bones test client (NOT the real client - that is Member A's)."""

    def __init__(self, addr):
        self.addr = addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)

    def send(self, ptype, tid, seq=0, payload=b""):
        self.sock.sendto(P.encode(ptype, tid, seq, payload), self.addr)

    def send_raw(self, raw):
        self.sock.sendto(raw, self.addr)

    def recv(self, timeout=1.0):
        self.sock.settimeout(timeout)
        try:
            return P.decode(self.sock.recvfrom(2048)[0])
        except socket.timeout:
            return None

    def close(self):
        self.sock.close()


def send_file(cl, tid, data, name="f.bin", chunk=1024, sha=None):
    """Lock-step transfer; returns the FIN-ACK packet."""
    cl.send(P.SYN, tid, 0, syn_payload(data, name, chunk, sha))
    assert cl.recv().ptype == P.SYN_ACK
    total = (len(data) + chunk - 1) // chunk
    for i in range(total):
        cl.send(P.DATA, tid, i, data[i * chunk:(i + 1) * chunk])
        ack = cl.recv()
        assert ack.ptype == P.ACK and ack.seq == i + 1
    cl.send(P.FIN, tid, total)
    return cl.recv()


@pytest.fixture
def make_server(tmp_path):
    started = []

    def factory(**kw):
        srv = Server("127.0.0.1", 0, str(tmp_path / "out"), **kw)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        started.append((srv, t))
        return srv

    yield factory
    for srv, t in started:
        srv.stop()
        t.join(2)


@pytest.fixture
def server(make_server):
    return make_server(linger=0.5, inactivity=5.0)


@pytest.fixture
def client(server):
    c = Client(server.address)
    yield c
    c.close()


def out(server, name="f.bin"):
    return os.path.join(server.outdir, name)


# ------------------------------------------------------------- helpers
def test_parse_syn_payload_roundtrip():
    data = b"hello"
    size, chunk, sha, name = parse_syn_payload(syn_payload(data, "a.txt", 512))
    assert (size, chunk, name) == (5, 512, "a.txt")
    assert sha == hashlib.sha256(data).digest()


@pytest.mark.parametrize("bad", [b"", b"x" * 10])
def test_parse_syn_rejects_short(bad):
    with pytest.raises(ValueError):
        parse_syn_payload(bad)


@pytest.mark.parametrize("raw,expected", [
    ("../../evil.txt", "evil.txt"), ("C:\\Windows\\x.dll", "x.dll"),
    ("a:b?.txt", "a_b_.txt"), ("ok.bin", "ok.bin")])
def test_safe_name(raw, expected):
    assert safe_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "..", "dir/"])
def test_safe_name_rejects(raw):
    with pytest.raises(ValueError):
        safe_name(raw)


# ------------------------------------------------- F2 handshake
def test_syn_gets_syn_ack_and_duplicate_syn_same_reply(server, client):
    data = b"abc"
    client.send(P.SYN, 7, 0, syn_payload(data))
    a = client.recv()
    client.send(P.SYN, 7, 0, syn_payload(data))
    b = client.recv()
    assert a.ptype == b.ptype == P.SYN_ACK and a.transfer_id == b.transfer_id == 7
    assert len(server.sessions) == 1


@pytest.mark.parametrize("chunk", [0, 1401, 5000])
def test_bad_chunk_size_gets_error(server, client, chunk):
    client.send(P.SYN, 1, 0, syn_payload(b"abc", chunk=chunk))
    assert client.recv().ptype == P.ERROR
    assert not server.sessions


def test_garbage_syn_gets_error(client):
    client.send(P.SYN, 1, 0, b"\x00" * 5)
    assert client.recv().ptype == P.ERROR


def test_path_traversal_name_stays_inside_outdir(server, client):
    data = os.urandom(100)
    fa = send_file(client, 5, data, name="../../evil.bin")
    assert fa.payload[0] == STATUS_OK
    assert os.path.exists(out(server, "evil.bin"))
    assert not os.path.exists(os.path.join(server.outdir, "..", "..", "evil.bin"))


# ------------------------------------------- F3/F8 correct transfers
@pytest.mark.parametrize("size", [0, 1, 1023, 1024, 1025, 5000, 100_000])
def test_file_sizes_hash_matches(server, client, size):
    data = os.urandom(size)
    fa = send_file(client, 11, data)
    assert fa.ptype == P.FIN_ACK and fa.payload[0] == STATUS_OK
    with open(out(server), "rb") as f:
        assert hashlib.sha256(f.read()).digest() == hashlib.sha256(data).digest()
    assert not [n for n in os.listdir(server.outdir) if n.endswith(".part")]


def test_one_megabyte(server, client):
    data = os.urandom(1_000_000)
    fa = send_file(client, 12, data)
    assert fa.payload[0] == STATUS_OK
    assert open(out(server), "rb").read() == data


def test_non_default_chunk_size(server, client):
    data = os.urandom(3000)
    assert send_file(client, 13, data, chunk=700).payload[0] == STATUS_OK
    assert open(out(server), "rb").read() == data


def test_hash_mismatch_reported_and_file_not_published(server, client):
    data = os.urandom(2000)
    fa = send_file(client, 14, data, sha=b"\x00" * 32)
    assert fa.payload[0] == STATUS_HASH_MISMATCH
    assert not os.path.exists(out(server))
    assert any(n.endswith(".bad") for n in os.listdir(server.outdir))


# ------------------------------------------------ F7 duplicates / order
def test_duplicate_data_not_written_twice(server, client):
    data = os.urandom(3000)
    client.send(P.SYN, 20, 0, syn_payload(data)); client.recv()
    client.send(P.DATA, 20, 0, data[:1024]); assert client.recv().seq == 1
    client.send(P.DATA, 20, 0, data[:1024]); assert client.recv().seq == 1   # dup
    client.send(P.DATA, 20, 1, data[1024:2048]); assert client.recv().seq == 2
    client.send(P.DATA, 20, 2, data[2048:]); assert client.recv().seq == 3
    client.send(P.FIN, 20, 3)
    assert client.recv().payload[0] == STATUS_OK
    assert open(out(server), "rb").read() == data
    assert server.finished[-1]["duplicates"] == 1


def test_out_of_order_discarded_and_reacked(server, client):
    data = os.urandom(3000)
    client.send(P.SYN, 21, 0, syn_payload(data)); client.recv()
    client.send(P.DATA, 21, 1, data[1024:2048])
    ack = client.recv()
    assert ack.ptype == P.ACK and ack.seq == 0
    for i in range(3):
        client.send(P.DATA, 21, i, data[i * 1024:(i + 1) * 1024])
        assert client.recv().seq == i + 1
    client.send(P.FIN, 21, 3)
    assert client.recv().payload[0] == STATUS_OK
    assert open(out(server), "rb").read() == data
    assert server.finished[-1]["out_of_order"] == 1


def test_corrupt_packet_dropped_silently(server, client):
    data = os.urandom(100)
    client.send(P.SYN, 22, 0, syn_payload(data)); client.recv()
    raw = bytearray(P.encode(P.DATA, 22, 0, data))
    raw[-1] ^= 0xFF
    client.send_raw(bytes(raw))
    assert client.recv(0.3) is None
    assert server.stats["corrupt_dropped"] == 1
    client.send(P.DATA, 22, 0, data)
    assert client.recv().seq == 1


def test_wrong_length_chunk_dropped(server, client):
    data = os.urandom(3000)
    client.send(P.SYN, 23, 0, syn_payload(data)); client.recv()
    client.send(P.DATA, 23, 0, data[:500])          # should be 1024 bytes
    assert client.recv(0.3) is None


def test_unknown_session_gets_error(client):
    client.send(P.DATA, 99, 0, b"x")
    assert client.recv().ptype == P.ERROR


# --------------------------------------------------- F9 teardown
def test_early_fin_ignored(server, client):
    data = os.urandom(3000)
    client.send(P.SYN, 30, 0, syn_payload(data)); client.recv()
    client.send(P.DATA, 30, 0, data[:1024]); client.recv()
    client.send(P.FIN, 30, 3)
    assert client.recv(0.3) is None


def test_fin_retransmit_during_linger_gets_same_fin_ack(server, client):
    data = os.urandom(10)
    fa1 = send_file(client, 31, data)
    client.send(P.FIN, 31, 1)
    fa2 = client.recv()
    assert fa2 == fa1


def test_session_removed_after_linger(make_server):
    srv = make_server(linger=0.3, inactivity=5.0)
    c = Client(srv.address)
    send_file(c, 32, b"hi")
    time.sleep(0.8)
    assert not srv.sessions
    c.send(P.FIN, 32, 1)
    assert c.recv().ptype == P.ERROR
    c.close()


# ------------------------------------------------- F12 inactivity
def test_inactivity_frees_state_and_part_file(make_server):
    srv = make_server(linger=0.3, inactivity=0.5)
    c = Client(srv.address)
    c.send(P.SYN, 40, 0, syn_payload(b"x" * 3000)); c.recv()
    assert srv.sessions
    time.sleep(1.3)
    assert not srv.sessions
    assert not [n for n in os.listdir(srv.outdir) if n.endswith(".part")]
    assert srv.finished[-1]["status"].startswith("ABORTED")
    c.close()


# ----------------------------------------------- F10 concurrency
def test_two_simultaneous_transfers(server):
    results = {}

    def worker(tid, name, data):
        c = Client(server.address)
        results[tid] = send_file(c, tid, data, name=name).payload[0]
        c.close()

    a, b = os.urandom(200_000), os.urandom(150_000)
    ts = [threading.Thread(target=worker, args=(50, "a.bin", a)),
          threading.Thread(target=worker, args=(51, "b.bin", b))]
    [t.start() for t in ts]; [t.join(20) for t in ts]
    assert results == {50: STATUS_OK, 51: STATUS_OK}
    assert open(out(server, "a.bin"), "rb").read() == a
    assert open(out(server, "b.bin"), "rb").read() == b


def test_same_transfer_id_from_two_clients_is_separate(server):
    c1, c2 = Client(server.address), Client(server.address)
    a, b = os.urandom(2000), os.urandom(2000)
    assert send_file(c1, 60, a, name="x.bin").payload[0] == STATUS_OK
    assert send_file(c2, 60, b, name="y.bin").payload[0] == STATUS_OK
    assert open(out(server, "x.bin"), "rb").read() == a
    assert open(out(server, "y.bin"), "rb").read() == b
    c1.close(); c2.close()
