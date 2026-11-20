"""Tests for the Week 4 experiment runner and the capture helper (Member B)."""
import csv
import os
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "experiments"))
import pcap_check  # type: ignore
import run_experiments as rx  # type: ignore

RUNNER = os.path.join(ROOT, "experiments", "run_experiments.py")


def run(args, timeout=240):
    return subprocess.run([sys.executable, RUNNER, *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ---- plan ------------------------------------------------------------------------
def test_scenario_grids_match_the_study_document():
    s2 = rx.scenario_configs("s2")
    assert sorted({c.delay_ms for c in s2}) == [0, 25, 50, 100] and {c.window for c in s2} == {1, 32}
    s3 = rx.scenario_configs("s3")
    assert sorted({c.loss_pct for c in s3}) == [0, 1, 2, 5, 10] and all(c.delay_ms == 50 for c in s3)
    s1 = rx.scenario_configs("s1")
    assert sorted({c.file_size for c in s1}) == [0, 1, 1024, 1048576, 10485760]
    o2 = rx.scenario_configs("o2")[0]
    assert (o2.window, o2.delay_ms, o2.loss_pct, o2.reps) == (32, 50, 5, 10)
    s4 = rx.scenario_configs("s4")
    assert sorted({c.window for c in s4}) == [1, 2, 4, 8, 16, 32, 64, 128] and all(c.rate_mbps == 10 for c in s4)


def test_dry_run_lists_every_configuration():
    r = run(["--scenario", "s2", "--dry-run"])
    assert r.returncode == 0 and "8 configurations" in r.stdout and "Rough total" in r.stdout


def test_number_normalisation_for_resume_keys():
    assert rx.nz(5) == rx.nz(5.0) == rx.nz("5.0") == "5"


def test_parse_client_output():
    text = ("Verification: OK\nCompletion time: 1.250 seconds\nGoodput: 6.711 Mbps\n"
            "DATA retransmissions: 7\nRetransmission ratio: 0.68%\n")
    p = rx.parse_client_output(text)
    assert p["ok"] and p["completion_s"] == 1.25 and p["goodput_mbps"] == 6.711
    assert p["retransmissions"] == 7 and p["ratio_pct"] == 0.68


# ---- capture cross-check ---------------------------------------------------------
def _hex(ptype, tid, seq):
    return (bytes([1, ptype, 0, 4]) + tid.to_bytes(4, "big") + seq.to_bytes(4, "big") + b"\0" * 4 + b"abcd").hex()


def test_pcap_counts_repeated_sequence_numbers():
    lines = [_hex(3, 7, 0), _hex(3, 7, 1), _hex(3, 7, 1), _hex(3, 7, 2), _hex(3, 7, 1),
             _hex(4, 7, 3), "", "zz", _hex(1, 7, 0)]            # ACK, junk and SYN are ignored
    assert pcap_check.count_retransmissions(lines) == (5, 3, 2)


def test_within_one_percent():
    assert pcap_check.within_one_percent(100, 100) and pcap_check.within_one_percent(100, 101)
    assert pcap_check.within_one_percent(1000, 1009)
    assert not pcap_check.within_one_percent(100, 110)


# ---- real end-to-end smoke run ---------------------------------------------------
def test_quick_run_writes_correct_csv_and_resume_skips(tmp_path):
    out = tmp_path / "s1.csv"
    r = run(["--scenario", "s1", "--quick", "--reps", "1", "--out", str(out)])
    assert r.returncode == 0, r.stdout + r.stderr
    data = rows(out)
    assert len(data) == 8 and all(d["hash_ok"] == "True" and d["status"] == "OK" for d in data)
    assert set(rx.FIELDS) == set(data[0].keys())
    assert {d["window"] for d in data} == {"1", "32"}
    r2 = run(["--scenario", "s1", "--quick", "--reps", "1", "--out", str(out), "--resume"])
    assert r2.returncode == 0 and "already done" in r2.stdout
    assert len(rows(out)) == 8                        # nothing was added twice


def test_impaired_run_records_rtt_and_server_counters(tmp_path):
    out = tmp_path / "s3.csv"
    r = run(["--scenario", "s3", "--quick", "--reps", "1", "--out", str(out)])
    assert r.returncode == 0, r.stdout + r.stderr
    data = rows(out)
    assert all(d["hash_ok"] == "True" for d in data)
    delayed = [d for d in data if d["delay_ms"] == "10" and d["loss_pct"] == "0"]
    assert all(15 < float(d["probe_rtt_ms"]) < 80 for d in delayed)        # about 2 x 10 ms
    lossy = [d for d in data if d["loss_pct"] == "5" and d["window"] == "1"]
    assert lossy and all(d["server_corrupt_dropped"] == "0" for d in data)  # probes never reach the server


def test_merge_combines_csv_files(tmp_path):
    for name, n in (("a", 2), ("b", 3)):
        with open(tmp_path / f"{name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=rx.FIELDS)
            w.writeheader()
            for i in range(n):
                w.writerow({k: "x" for k in rx.FIELDS})
    rx.merge_results(tmp_path)
    assert len(rows(tmp_path / "all_results.csv")) == 5
