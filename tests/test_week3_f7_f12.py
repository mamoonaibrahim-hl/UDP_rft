"""Week 3 (Member B): end-to-end tests of F7 to F12 with the REAL client.

Every test sends a file through testbed/impair_proxy.py (loss, duplication,
reordering, corruption, outage) and checks both the delivered file and the
server's counters. Run:  python -m pytest tests\\test_week3_f7_f12.py -v
Set RUN_SLOW=1 to include the 25-second "server dies" test.
"""
import csv
import os
import threading
import time

import pytest

from rft.server import Server
from tests.conftest import sha_of, summary

KB = 1024


# ---- milestone: window mode correct under loss ---------------------------------
@pytest.mark.parametrize("window", [1, 8, 32])
def test_clean_transfer_all_window_sizes(server, make_proxy, make_file, run_client, window):
    path, sha = make_file(300 * KB)
    proxy = make_proxy()
    r = run_client(path, proxy.address[1], window)
    assert r.returncode == 0, r.stderr
    assert summary(r.stdout)["ok"]
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha


@pytest.mark.parametrize("window", [1, 8, 32])
def test_transfer_correct_under_5_percent_loss(server, make_proxy, make_file, run_client, window):
    path, sha = make_file(150 * KB)
    proxy = make_proxy(loss=5, seed=7)
    r = run_client(path, proxy.address[1], window)
    assert r.returncode == 0, r.stderr
    s = summary(r.stdout)
    assert s["ok"] and s["retransmissions"] > 0
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha


# ---- F7: duplicates, reordering; F8: corruption --------------------------------
def test_duplicates_are_never_written_twice(server, make_proxy, make_file, run_client):
    path, sha = make_file(200 * KB)
    proxy = make_proxy(duplicate=30, seed=3)
    r = run_client(path, proxy.address[1], window=8)
    assert r.returncode == 0, r.stderr
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha
    done = server.finished[-1]
    assert done["duplicates"] > 0 and done["bytes"] == 200 * KB


def test_reordered_packets_are_discarded_and_recovered(server, make_proxy, make_file, run_client):
    path, sha = make_file(200 * KB)
    proxy = make_proxy(delay_ms=10, reorder=30, seed=5)
    r = run_client(path, proxy.address[1], window=8)
    assert r.returncode == 0, r.stderr
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha
    assert server.finished[-1]["out_of_order"] > 0


def test_corrupted_packets_are_dropped_by_crc(server, make_proxy, make_file, run_client):
    path, sha = make_file(150 * KB)
    proxy = make_proxy(corrupt=5, seed=11)
    r = run_client(path, proxy.address[1], window=8)
    assert r.returncode == 0, r.stderr
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha
    assert server.stats["corrupt_dropped"] > 0


# ---- F10: concurrency through a lossy path ------------------------------------
def test_two_clients_at_once_through_lossy_path(server, make_proxy, make_file, run_client):
    a, sha_a = make_file(150 * KB, "a.bin")
    b, sha_b = make_file(100 * KB, "b.bin")
    proxy = make_proxy(loss=2, delay_ms=5, seed=2)
    results = {}

    def go(name, path):
        results[name] = run_client(path, proxy.address[1], window=8)

    ts = [threading.Thread(target=go, args=("a", a)), threading.Thread(target=go, args=("b", b))]
    [t.start() for t in ts]
    [t.join(120) for t in ts]
    assert results["a"].returncode == 0 and results["b"].returncode == 0
    assert sha_of(os.path.join(server.outdir, "a.bin")) == sha_a
    assert sha_of(os.path.join(server.outdir, "b.bin")) == sha_b


# ---- F12 / O5: failure and recovery -------------------------------------------
def test_recovers_after_total_outage(server, make_proxy, make_file, run_client):
    """S5a: blackout 1 s after the first packet, lasting 2 s; transfer must resume."""
    path, sha = make_file(600 * KB)
    proxy = make_proxy(delay_ms=20, outage=(1.0, 2.0), seed=4)
    r = run_client(path, proxy.address[1], window=8)
    assert r.returncode == 0, r.stderr
    s = summary(r.stdout)
    assert s["ok"] and s["seconds"] >= 2.0          # it really stalled
    assert sha_of(os.path.join(server.outdir, "src.bin")) == sha


def test_missing_file_fails_cleanly(run_client, tmp_path):
    r = run_client(tmp_path / "does_not_exist.bin", 5005)
    assert r.returncode == 1 and "Transfer failed" in r.stderr


def test_no_server_gives_up_within_30_seconds(run_client, tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"hello")
    start = time.monotonic()
    r = run_client(path, 59999)                      # nothing listens here
    assert r.returncode == 1 and "Transfer failed" in r.stderr
    assert time.monotonic() - start < 30


@pytest.mark.skipif(not os.environ.get("RUN_SLOW"), reason="set RUN_SLOW=1 (takes ~25 s)")
def test_server_dies_midtransfer_client_aborts(server, make_proxy, make_file, run_client):
    """S5b / O5: client must abort with an error within 30 s of the last ACK."""
    path, _ = make_file(900 * KB)
    proxy = make_proxy(delay_ms=20)
    threading.Timer(1.0, server.stop).start()
    start = time.monotonic()
    r = run_client(path, proxy.address[1], window=4, timeout=90)
    assert r.returncode == 1 and "Transfer failed" in r.stderr
    assert time.monotonic() - start < 40


# ---- F11: server statistics CSV for the experiment runner -----------------------
def test_server_writes_stats_csv(tmp_path, make_file, run_client):
    stats = tmp_path / "server_stats.csv"
    srv = Server("127.0.0.1", 0, str(tmp_path / "rx"), linger=0.3, stats_csv=str(stats))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        path, _ = make_file(50 * KB)
        r = run_client(path, srv.address[1], window=4)
        assert r.returncode == 0, r.stderr
    finally:
        srv.stop()
        t.join(3)
    rows = list(csv.DictReader(open(stats, encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["file"] == "src.bin" and rows[0]["status"] == "0"
    assert int(rows[0]["bytes"]) == 50 * KB and int(rows[0]["chunks"]) == 50
