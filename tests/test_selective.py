"""Tests for extension E1 (selective retransmission): bitmap helpers, selective receiver,
and the selective sender end to end. Run: python -m pytest tests\\test_selective.py -v"""
import hashlib
import os
import socket
import struct

import pytest

from rft import packet as P
from rft.sack import SACK_RANGE, make_sack, parse_sack
from tests.conftest import sha_of, summary

KB = 1024


# ---- bitmap helpers -----------------------------------------------------------------
def test_empty_bitmap_when_no_gaps():
    assert make_sack(5, []) == b""
    assert parse_sack(5, b"") == set()


def test_bitmap_round_trip():
    held = {6, 7, 9, 20, 5 + SACK_RANGE}
    assert parse_sack(5, make_sack(5, held)) == held


def test_bitmap_bit_positions():
    assert make_sack(0, [1]) == b"\x01"            # chunk expected+1 is bit 0
    assert make_sack(0, [2]) == b"\x02"
    assert make_sack(0, [9]) == b"\x00\x01"        # chunk expected+9 is bit 0 of byte 1
    assert make_sack(0, [0, SACK_RANGE + 5]) == b""  # outside the range is ignored


# ---- selective receiver, raw packets ---------------------------------------------------
def syn(data, selective, name="s.bin", chunk=1024):
    n = name.encode()
    payload = struct.pack("!QH32sH", len(data), chunk, hashlib.sha256(data).digest(), len(n)) + n
    return payload + (b"\x01" if selective else b"")


def exchange(sock, addr, ptype, tid, seq, payload=b""):
    sock.sendto(P.encode(ptype, tid, seq, payload), addr)
    return P.decode(sock.recvfrom(2048)[0])


@pytest.fixture
def raw(server):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    yield s, server.address
    s.close()


def test_selective_server_buffers_early_chunks(server, raw):
    sock, addr = raw
    data = os.urandom(4 * KB)
    chunks = [data[i * KB:(i + 1) * KB] for i in range(4)]
    assert exchange(sock, addr, P.SYN, 1, 0, syn(data, True)).ptype == P.SYN_ACK
    a = exchange(sock, addr, P.DATA, 1, 2, chunks[2])        # chunk 2 arrives first
    assert (a.ptype, a.seq, parse_sack(a.seq, a.payload)) == (P.ACK, 0, {2})
    a = exchange(sock, addr, P.DATA, 1, 1, chunks[1])        # chunk 1: still waiting for 0
    assert (a.seq, parse_sack(a.seq, a.payload)) == (0, {1, 2})
    a = exchange(sock, addr, P.DATA, 1, 0, chunks[0])        # chunk 0 closes the gap
    assert (a.seq, a.payload) == (3, b"")
    a = exchange(sock, addr, P.DATA, 1, 3, chunks[3])
    assert a.seq == 4
    fa = exchange(sock, addr, P.FIN, 1, 4)
    assert fa.ptype == P.FIN_ACK and fa.payload[0] == 0
    assert sha_of(os.path.join(server.outdir, "s.bin")) == hashlib.sha256(data).hexdigest()
    assert server.finished[-1]["out_of_order"] == 2


def test_selective_server_counts_duplicates_of_buffered_chunks(server, raw):
    sock, addr = raw
    data = os.urandom(3 * KB)
    exchange(sock, addr, P.SYN, 2, 0, syn(data, True))
    exchange(sock, addr, P.DATA, 2, 1, data[KB:2 * KB])
    a = exchange(sock, addr, P.DATA, 2, 1, data[KB:2 * KB])  # same early chunk again
    assert parse_sack(a.seq, a.payload) == {1}
    for i in (0, 2):
        exchange(sock, addr, P.DATA, 2, i, data[i * KB:(i + 1) * KB])
    assert exchange(sock, addr, P.FIN, 2, 3).payload[0] == 0
    assert server.finished[-1]["duplicates"] == 1


def test_classic_session_still_discards_early_chunks_with_plain_acks(server, raw):
    sock, addr = raw
    data = os.urandom(3 * KB)
    exchange(sock, addr, P.SYN, 3, 0, syn(data, False))
    a = exchange(sock, addr, P.DATA, 3, 2, data[2 * KB:])
    assert (a.seq, a.payload) == (0, b"")                    # no bitmap, chunk thrown away
    session = [x for x in server.sessions.values() if x.tid == 3][0]
    assert session.buffer == {}


# ---- selective sender end to end --------------------------------------------------------
def test_selective_transfer_correct_under_loss(server, make_proxy, make_file, run_client):
    path, sha = make_file(200 * KB)
    proxy = make_proxy(loss=5, seed=21)
    r = run_client(path, proxy.address[1], window=32, extra=["--selective"])
    assert r.returncode == 0, r.stderr
    assert summary(r.stdout)["ok"]
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha


def test_selective_transfer_correct_with_reordering_and_duplicates(server, make_proxy, make_file, run_client):
    path, sha = make_file(200 * KB)
    proxy = make_proxy(delay_ms=10, reorder=30, duplicate=10, seed=22)
    r = run_client(path, proxy.address[1], window=16, extra=["--selective"])
    assert r.returncode == 0, r.stderr
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha


def test_selective_retransmits_far_less_than_go_back_n(server, make_proxy, make_file, run_client):
    path, _ = make_file(200 * KB)
    proxy = make_proxy(loss=5, seed=23)
    gbn = summary(run_client(path, proxy.address[1], window=32).stdout)
    sr = summary(run_client(path, proxy.address[1], window=32, extra=["--selective"]).stdout)
    assert gbn["ok"] and sr["ok"]
    assert sr["retransmissions"] < gbn["retransmissions"] / 2


def test_selective_window_over_256_is_refused(server, make_proxy, make_file, run_client):
    path, _ = make_file(10 * KB)
    r = run_client(path, make_proxy().address[1], window=300, extra=["--selective"])
    assert r.returncode != 0
