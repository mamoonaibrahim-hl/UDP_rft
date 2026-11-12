"""Tests for testbed/impair_proxy.py, echo_server.py, probe.py (Member B, Week 1)."""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "testbed"))
from echo_server import EchoServer      # noqa: E402
from impair_proxy import Impairment, Proxy  # noqa: E402
from probe import make_payload, run_probe   # noqa: E402

DATA = bytes(range(100))


def test_no_impairment_passes_unchanged():
    assert Impairment(seed=1).apply(DATA, 0.0) == [(0.0, DATA)]


def test_full_loss_drops_everything():
    imp = Impairment(loss=100, seed=1)
    assert all(imp.apply(DATA, 0.0) == [] for _ in range(50))
    assert imp.stats["lost"] == 50


def test_loss_rate_close_to_target():
    imp = Impairment(loss=10, seed=42)
    lost = sum(1 for _ in range(20000) if not imp.apply(DATA, 0.0))
    assert 0.09 < lost / 20000 < 0.11


def test_delay_and_jitter_bounds():
    out = Impairment(delay_ms=50, jitter_ms=10, seed=3)
    delays = [out.apply(DATA, 0.0)[0][0] for _ in range(500)]
    assert min(delays) >= 0.040 and max(delays) <= 0.060


def test_duplicate_gives_two_copies():
    res = Impairment(duplicate=100, seed=1).apply(DATA, 0.0)
    assert len(res) == 2 and res[0][1] == res[1][1] == DATA


def test_corrupt_changes_exactly_one_byte():
    (_, bad), = Impairment(corrupt=100, seed=1).apply(DATA, 0.0)
    assert len(bad) == len(DATA) and sum(a != b for a, b in zip(bad, DATA)) == 1


def test_reorder_makes_some_packets_overtake():
    imp = Impairment(delay_ms=10, reorder=25, seed=5)
    delays = [imp.apply(DATA, 0.0)[0][0] for _ in range(2000)]
    immediate = sum(1 for d in delays if d == 0.0) / 2000
    assert 0.20 < immediate < 0.30


def test_outage_window_drops_only_inside_window():
    imp = Impairment(outage=(2.0, 5.0), seed=1)
    assert imp.apply(DATA, 100.0)          # first packet sets t0, delivered
    assert imp.apply(DATA, 101.9)          # before window
    assert imp.apply(DATA, 102.5) == []    # inside
    assert imp.apply(DATA, 106.9) == []    # inside
    assert imp.apply(DATA, 107.1)          # after


def test_same_seed_is_reproducible():
    a = [bool(Impairment(loss=30, seed=7).apply(DATA, 0)) for _ in range(1)]
    r1, r2 = Impairment(loss=30, seed=7), Impairment(loss=30, seed=7)
    assert [bool(r1.apply(DATA, 0)) for _ in range(200)] == [bool(r2.apply(DATA, 0)) for _ in range(200)]


# ---------------------------------------------- end-to-end with sockets
@pytest.fixture
def chain():
    """probe -> proxy -> echo, all on loopback with free ports."""
    echo = EchoServer("127.0.0.1", 0)
    made = []

    def build(**kw):
        proxy = Proxy(("127.0.0.1", 0), echo.address, Impairment(seed=1, **kw),
                      Impairment(seed=2, **kw))
        made.append(proxy)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        return proxy

    threading.Thread(target=echo.serve_forever, daemon=True).start()
    yield build
    for p in made:
        p.stop()
    echo.stop()


def test_probe_clean_path(chain):
    proxy = chain()
    r = run_probe(port=proxy.address[1], count=50, interval=0.005, timeout=0.5)
    assert r["received"] == 50 and r["duplicates"] == 0 and r["corrupted"] == 0


def test_probe_rtt_is_about_twice_one_way_delay(chain):
    proxy = chain(delay_ms=40)
    r = run_probe(port=proxy.address[1], count=30, interval=0.01, timeout=0.5)
    assert r["received"] == 30
    assert 75 <= r["rtt_avg_ms"] <= 130          # 2 x 40 ms plus scheduling noise


def test_probe_sees_loss_in_both_directions(chain):
    proxy = chain(loss=20)                         # expected 1-(0.8)^2 = 36 %
    r = run_probe(port=proxy.address[1], count=400, interval=0.001, timeout=0.5)
    assert 25 <= r["loss_pct"] <= 47


def test_probe_sees_duplicates_and_corruption(chain):
    r = run_probe(port=chain(duplicate=30).address[1], count=200, interval=0.002, timeout=0.5)
    assert r["duplicates"] > 20
    r = run_probe(port=chain(corrupt=30).address[1], count=200, interval=0.002, timeout=0.5)
    assert r["corrupted"] > 20


def test_make_payload_is_deterministic():
    assert make_payload(5, 64) == make_payload(5, 64) and len(make_payload(5, 64)) == 64
