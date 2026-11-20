#!/usr/bin/env python
"""Experiment runner (Member B, Week 4): runs the evaluation scenarios of the study
document (section 7.2) on Windows through the impairment proxy and stores one CSV
row per run.

For every configuration the runner starts a fresh server and proxy (separate
processes), measures the real RTT with the probe, runs the REAL client N times,
checks the received file's SHA-256 itself, and reads the server's counters.

    python experiments\\run_experiments.py --scenario s1 --dry-run     # show the plan
    python experiments\\run_experiments.py --scenario s1 --quick --reps 1   # 1-minute smoke test
    python experiments\\run_experiments.py --scenario core --resume   # S1, S2, S3, O2 (unattended)
    python experiments\\run_experiments.py --merge                     # results\\all_results.csv

Scenarios: calibrate, s1, s2, s3, o2, s4, s6, core (= s1 s2 s3 o2).
S5 (outage / server killed) and S7 (concurrency) are added in Week 5.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import math
import os
import random
import re
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "testbed"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
PY = sys.executable
MiB = 1024 * 1024

FIELDS = ["scenario", "mode", "window", "delay_ms", "loss_pct", "duplicate_pct", "corrupt_pct",
          "reorder_pct", "rate_mbps", "file_size", "rep", "completion_s", "goodput_mbps",
          "retransmissions", "retrans_ratio_pct", "server_duplicates", "server_out_of_order",
          "server_corrupt_dropped", "hash_ok", "status", "probe_rtt_ms", "pcap_retransmissions",
          "pcap_match", "wall_s", "timestamp"]
KEY_FIELDS = ["scenario", "mode", "window", "delay_ms", "loss_pct", "duplicate_pct", "corrupt_pct",
              "reorder_pct", "rate_mbps", "file_size", "rep"]


@dataclass(frozen=True)
class Config:
    scenario: str
    window: int
    delay_ms: float = 0.0
    loss_pct: float = 0.0
    duplicate_pct: float = 0.0
    corrupt_pct: float = 0.0
    reorder_pct: float = 0.0
    rate_mbps: float = 0.0
    file_size: int = MiB
    reps: int = 3

    @property
    def mode(self):
        return "stop-and-wait" if self.window == 1 else "sliding"

    def label(self):
        parts = [f"{self.scenario}", f"W{self.window}", f"{self.file_size}B", f"d{self.delay_ms:g}", f"l{self.loss_pct:g}"]
        for name, v in (("dup", self.duplicate_pct), ("cor", self.corrupt_pct), ("reo", self.reorder_pct), ("rate", self.rate_mbps)):
            if v:
                parts.append(f"{name}{v:g}")
        return "_".join(parts)


# ----------------------------------------------------------------------------- scenarios
def scenario_configs(name, quick=False, reps=None, size=None):
    SW, SL = 1, 32
    fs = size or (65536 if quick else MiB)
    r = reps if reps else (1 if quick else 3)
    out = []
    if name == "calibrate":
        for w in (1, 32, 128):
            out.append(Config("calibrate", w, file_size=size or (MiB if quick else 10 * MiB), reps=reps or 3))
    elif name == "s1":
        sizes = [0, 1, 1024, 65536] if quick else [0, 1, 1024, MiB, 10 * MiB]
        for s in ([size] if size else sizes):
            for w in (SW, SL):
                out.append(Config("s1", w, file_size=s, reps=r))
    elif name == "s2":
        for d in ([0, 10] if quick else [0, 25, 50, 100]):
            for w in (SW, SL):
                out.append(Config("s2", w, delay_ms=d, file_size=fs, reps=r))
    elif name == "s3":
        d = 10 if quick else 50
        for p in ([0, 5] if quick else [0, 1, 2, 5, 10]):
            for w in (SW, SL):
                out.append(Config("s3", w, delay_ms=d, loss_pct=p, file_size=fs, reps=r))
    elif name == "o2":
        out.append(Config("o2", SL, delay_ms=10 if quick else 50, loss_pct=5, file_size=fs, reps=reps or (2 if quick else 10)))
    elif name == "s4":
        for p in (0, 2):
            for w in ([1, 8] if quick else [1, 2, 4, 8, 16, 32, 64, 128]):
                out.append(Config("s4", w, delay_ms=10 if quick else 50, loss_pct=p, rate_mbps=10, file_size=fs, reps=r))
    elif name == "s6":
        out.append(Config("s6", SL, duplicate_pct=5, file_size=fs, reps=r))
        out.append(Config("s6", SL, delay_ms=10, reorder_pct=25, file_size=fs, reps=r))
        out.append(Config("s6", SL, corrupt_pct=1, file_size=fs, reps=r))
    else:
        raise SystemExit(f"unknown scenario {name!r}")
    return out


def estimate_seconds(cfg: Config):
    """Crude guess (within a factor of about 2) used only for the dry-run plan."""
    chunks = max(1, math.ceil(cfg.file_size / 1024))
    rtt = 2 * cfg.delay_ms / 1000 + (0.02 if cfg.delay_ms else 0)
    p = cfg.loss_pct / 100
    q = 1 - (1 - p) ** 2
    if cfg.window == 1:
        t = chunks * (rtt + 0.0004) + chunks * q * 0.5
    else:
        t = (chunks / cfg.window) * (rtt + 0.001) + chunks * q * 0.5 / min(cfg.window, 8) + chunks * 0.0004
    if cfg.rate_mbps:
        t = max(t, chunks * 1024 * 8 / (cfg.rate_mbps * 1e6))
    return (t + 1.5) * cfg.reps + 4


# ----------------------------------------------------------------------------- helpers
def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_source_file(directory: Path, size: int):
    """Random but reproducible file (fixed seed), cached on disk."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"src_{size}.bin"
    if not path.exists() or path.stat().st_size != size:
        path.write_bytes(random.Random(12345 + size).randbytes(size))
    return path


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def wait_for_text(path, text, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if text in Path(path).read_text(errors="replace"):
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def start_process(cmd, log_path):
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    log = open(log_path, "w")
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, **kwargs)
    proc._logfile = log
    return proc


def stop_process(proc):
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc._logfile.close()
    except Exception:
        pass


def parse_client_output(stdout):
    def num(pattern):
        m = re.search(pattern, stdout)
        return float(m.group(1)) if m else None
    return {
        "ok": "Verification: OK" in stdout,
        "completion_s": num(r"Completion time: ([\d.]+) seconds"),
        "goodput_mbps": num(r"\nGoodput: ([\d.]+) Mbps"),
        "retransmissions": num(r"DATA retransmissions: (\d+)\s*\nRetransmission ratio"),
        "ratio_pct": num(r"Retransmission ratio: ([\d.]+)%"),
    }


def read_last_server_row(stats_csv):
    try:
        with open(stats_csv, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return rows[-1] if rows else None
    except OSError:
        return None


def load_done_keys(path):
    done = set()
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                done.add(tuple(row.get(k, "") if k in ("scenario", "mode") else nz(row.get(k, "")) for k in KEY_FIELDS))
    return done


def nz(v):
    """Normalise numbers so 5, 5.0 and '5.0' all give the same text (used in CSV and resume keys)."""
    try:
        return f"{float(v):g}"
    except (TypeError, ValueError):
        return str(v)


def key_of(cfg: Config, rep: int):
    vals = {"scenario": cfg.scenario, "mode": cfg.mode, "window": cfg.window, "delay_ms": cfg.delay_ms,
            "loss_pct": cfg.loss_pct, "duplicate_pct": cfg.duplicate_pct, "corrupt_pct": cfg.corrupt_pct,
            "reorder_pct": cfg.reorder_pct, "rate_mbps": cfg.rate_mbps, "file_size": cfg.file_size, "rep": rep}
    return tuple(vals[k] if k in ("scenario", "mode") else nz(vals[k]) for k in KEY_FIELDS)


def measure_rtt(delay_ms, rate_mbps, work: Path):
    """Real round-trip time of the emulated path: probe -> delay-only proxy -> echo server.
    (Probing the real server would pollute its counters, so a separate echo server is used.)"""
    from probe import run_probe
    eport, pport = free_udp_port(), free_udp_port()
    echo = prox = None
    try:
        echo = start_process([PY, "-u", str(ROOT / "testbed" / "echo_server.py"), "--port", str(eport)], work / "echo.log")
        prox = start_process([PY, "-u", str(ROOT / "testbed" / "impair_proxy.py"), "--listen", f"127.0.0.1:{pport}",
                              "--target", f"127.0.0.1:{eport}", "--delay", str(delay_ms), "--rate-mbps", str(rate_mbps)],
                             work / "rtt_proxy.log")
        if not (wait_for_text(work / "echo.log", "listening") and wait_for_text(work / "rtt_proxy.log", "proxy ")):
            return ""
        r = run_probe("127.0.0.1", pport, count=30, size=64, interval=0.02, timeout=1.0)
        return round(r["rtt_avg_ms"], 2) if r["rtt_avg_ms"] is not None else ""
    finally:
        stop_process(prox)
        stop_process(echo)


# ----------------------------------------------------------------------------- capture (optional)
class Capture:
    """Optional tshark capture of one run. Never stops the experiment if it fails."""

    def __init__(self, path, ports):
        self.proc = None
        self.path = path
        try:
            from pcap_check import find_tshark
            tshark = find_tshark()
            if not tshark:
                print("   capture skipped: tshark not found")
                return
            listing = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=30).stdout
            iface = next((ln.split(".")[0].strip() for ln in listing.splitlines() if "loopback" in ln.lower()), None)
            if not iface:
                print("   capture skipped: no loopback interface (install Npcap with loopback support)")
                return
            cmd = [tshark, "-i", iface, "-f", f"udp port {ports[0]} or udp port {ports[1]}", "-w", str(path), "-q"]
            kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {}
            self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
            time.sleep(1.5)
        except Exception as e:  # noqa: BLE001
            print(f"   capture skipped: {e}")

    def stop(self):
        if not self.proc:
            return False
        time.sleep(0.7)
        try:
            if sys.platform == "win32":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.proc.send_signal(signal.SIGINT)
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        return os.path.exists(self.path)


# ----------------------------------------------------------------------------- main run logic
def run_config(cfg: Config, args, writer, out_file, done, work: Path, index, total):
    label = cfg.label()
    todo = [rep for rep in range(1, cfg.reps + 1) if key_of(cfg, rep) not in done]
    if not todo:
        print(f"[{index}/{total}] {label}: already done, skipped")
        return
    cfg_dir = work / label
    cfg_dir.mkdir(parents=True, exist_ok=True)
    stats_csv = cfg_dir / "server_stats.csv"
    if stats_csv.exists():
        stats_csv.unlink()
    outdir = cfg_dir / "received"
    sport, pport = free_udp_port(), free_udp_port()
    src = make_source_file(work / "data", cfg.file_size)
    src_sha = sha256_file(src)

    server = proxy = None
    try:
        server = start_process([PY, "-u", "-m", "rft.server", "--host", "127.0.0.1", "--port", str(sport),
                                "--outdir", str(outdir), "--stats-csv", str(stats_csv), "--linger", "0.5"],
                               cfg_dir / "server.log")
        pcmd = [PY, "-u", str(ROOT / "testbed" / "impair_proxy.py"), "--listen", f"127.0.0.1:{pport}",
                "--target", f"127.0.0.1:{sport}", "--delay", str(cfg.delay_ms), "--loss", str(cfg.loss_pct),
                "--duplicate", str(cfg.duplicate_pct), "--corrupt", str(cfg.corrupt_pct),
                "--reorder", str(cfg.reorder_pct), "--rate-mbps", str(cfg.rate_mbps),
                "--seed", str(1000 + index)]
        proxy = start_process(pcmd, cfg_dir / "proxy.log")
        if not (wait_for_text(cfg_dir / "server.log", "listening") and wait_for_text(cfg_dir / "proxy.log", "proxy ")):
            raise RuntimeError(f"server or proxy did not start (see {cfg_dir})")

        rtt = measure_rtt(cfg.delay_ms, cfg.rate_mbps, cfg_dir)
        print(f"[{index}/{total}] {label}: probe RTT {rtt} ms, runs {todo}", flush=True)

        prev_corrupt = 0
        for rep in todo:
            capture = None
            cap_path = work.parent / "captures" / f"{label}.pcapng"
            if args.capture and rep == todo[0]:
                cap_path.parent.mkdir(parents=True, exist_ok=True)
                capture = Capture(cap_path, (pport, sport))
            t0 = time.monotonic()
            log_path = cfg_dir / f"client_rep{rep}.csv"
            cmd = [PY, "-m", "rft.client", str(src), "--host", "127.0.0.1", "--port", str(pport),
                   "--window", str(cfg.window), "--log", str(log_path), *args.client_args]
            status, parsed = "OK", {}
            try:
                r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=args.timeout)
                parsed = parse_client_output(r.stdout)
                if r.returncode != 0 or not parsed["ok"]:
                    first = (r.stderr.strip().splitlines() or ["no error text"])[0]
                    status = f"FAILED: {first[:80]}"
            except subprocess.TimeoutExpired:
                status = f"TIMEOUT after {args.timeout:g} s"
            wall = time.monotonic() - t0

            received = outdir / src.name
            hash_ok = received.exists() and sha256_file(received) == src_sha
            if status == "OK" and not hash_ok:
                status = "FAILED: hash differs"
            row_srv = read_last_server_row(stats_csv) if status == "OK" else None
            dup = ooo = cor = ""
            if row_srv:
                dup, ooo = row_srv["duplicates"], row_srv["out_of_order"]
                total_cor = int(row_srv["corrupt_dropped_total"])
                cor, prev_corrupt = total_cor - prev_corrupt, total_cor

            pcap_retr = pcap_match = ""
            if capture is not None:
                if capture.stop() and status == "OK":
                    try:
                        from pcap_check import count_retransmissions, read_capture, within_one_percent
                        _, _, pcap_retr = count_retransmissions(read_capture(cap_path, pport))
                        pcap_match = within_one_percent(pcap_retr, int(parsed.get("retransmissions") or 0))
                    except Exception as e:  # noqa: BLE001
                        print(f"   capture check skipped: {e}")

            if os.path.exists(received):
                try:
                    os.remove(received)
                except OSError:
                    pass
            row = {"scenario": cfg.scenario, "mode": cfg.mode, "window": cfg.window, "delay_ms": nz(cfg.delay_ms),
                   "loss_pct": nz(cfg.loss_pct), "duplicate_pct": nz(cfg.duplicate_pct), "corrupt_pct": nz(cfg.corrupt_pct),
                   "reorder_pct": nz(cfg.reorder_pct), "rate_mbps": nz(cfg.rate_mbps), "file_size": cfg.file_size, "rep": rep,
                   "completion_s": parsed.get("completion_s", ""), "goodput_mbps": parsed.get("goodput_mbps", ""),
                   "retransmissions": "" if parsed.get("retransmissions") is None else int(parsed["retransmissions"]),
                   "retrans_ratio_pct": parsed.get("ratio_pct", ""), "server_duplicates": dup,
                   "server_out_of_order": ooo, "server_corrupt_dropped": cor, "hash_ok": hash_ok,
                   "status": status, "probe_rtt_ms": rtt, "pcap_retransmissions": pcap_retr,
                   "pcap_match": pcap_match, "wall_s": round(wall, 2),
                   "timestamp": datetime.datetime.now().isoformat(timespec="seconds")}
            writer.writerow(row)
            out_file.flush()
            print(f"   rep {rep}: {status}  time {row['completion_s']} s  goodput {row['goodput_mbps']} Mbps  "
                  f"retrans {row['retransmissions']}  hash_ok {hash_ok}", flush=True)
    finally:
        stop_process(proxy)
        stop_process(server)


def run_scenario(name, args):
    configs = scenario_configs(name, args.quick, args.reps, args.size)
    total = len(configs)
    if args.dry_run:
        grand = 0
        print(f"Scenario {name}: {total} configurations")
        for i, c in enumerate(configs, 1):
            est = estimate_seconds(c)
            grand += est
            print(f"  {i:2}. {c.label():45} {c.reps} reps   about {est / 60:5.1f} min")
        print(f"  Rough total: {grand / 60:.0f} minutes (a guess; the first real run gives the true figure)")
        return
    out_path = Path(args.out) if args.out else ROOT / "results" / f"{name}.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    work = out_path.parent / "work" / name
    work.mkdir(parents=True, exist_ok=True)
    done = load_done_keys(out_path) if args.resume else set()
    is_new = not out_path.exists() or not args.resume
    with open(out_path, "w" if not args.resume else "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if is_new or out_path.stat().st_size == 0:
            writer.writeheader()
        start = time.monotonic()
        for i, cfg in enumerate(configs, 1):
            run_config(cfg, args, writer, f, done, work, i, total)
        print(f"Scenario {name} finished in {(time.monotonic() - start) / 60:.1f} min -> {out_path}")


def merge_results(results_dir: Path):
    rows = []
    for p in sorted(results_dir.glob("*.csv")):
        if p.name in ("all_results.csv", "sample_results.csv") or p.name.startswith("server_stats"):
            continue
        with open(p, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames and set(KEY_FIELDS) <= set(reader.fieldnames):
                rows.extend(reader)
    target = results_dir / "all_results.csv"
    with open(target, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"merged {len(rows)} rows -> {target}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run evaluation scenarios through the impairment proxy")
    ap.add_argument("--scenario", default=None, help="calibrate, s1, s2, s3, o2, s4, s6 or core")
    ap.add_argument("--reps", type=int, default=None, help="repetitions per configuration (default 3; o2 uses 10)")
    ap.add_argument("--quick", action="store_true", help="small files and a reduced grid, for a smoke test")
    ap.add_argument("--size", type=int, default=None, help="override the file size in bytes")
    ap.add_argument("--resume", action="store_true", help="append to the CSV and skip runs already in it")
    ap.add_argument("--capture", action="store_true", help="tshark capture of the first run of each configuration")
    ap.add_argument("--timeout", type=float, default=900, help="per-run limit in seconds")
    ap.add_argument("--out", default=None, help="output CSV (default results/<scenario>.csv)")
    ap.add_argument("--client-args", default="", help="extra client options, e.g. \"--chunk-size 1400\"")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and a rough time estimate")
    ap.add_argument("--merge", action="store_true", help="combine results/*.csv into results/all_results.csv")
    args = ap.parse_args(argv)
    args.client_args = shlex.split(args.client_args)
    if args.merge:
        merge_results(ROOT / "results")
        return 0
    if not args.scenario:
        ap.error("--scenario is required (or use --merge)")
    names = ["s1", "s2", "s3", "o2"] if args.scenario == "core" else [args.scenario]
    if args.out and len(names) > 1:
        ap.error("--out works with a single scenario")
    try:
        for n in names:
            run_scenario(n, args)
    except KeyboardInterrupt:
        print("\nstopped by user; rerun with --resume to continue")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
