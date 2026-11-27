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

FIELDS = ["scenario", "mode", "window", "delay_ms", "jitter_ms", "loss_pct", "duplicate_pct", "corrupt_pct",
          "reorder_pct", "rate_mbps", "file_size", "rep", "completion_s", "goodput_mbps",
          "retransmissions", "retrans_ratio_pct", "server_duplicates", "server_out_of_order",
          "server_corrupt_dropped", "hash_ok", "status", "probe_rtt_ms", "pcap_retransmissions",
          "pcap_match", "wall_s", "timestamp"]
KEY_FIELDS = ["scenario", "mode", "window", "delay_ms", "jitter_ms", "loss_pct", "duplicate_pct", "corrupt_pct",
              "reorder_pct", "rate_mbps", "file_size", "rep"]


@dataclass(frozen=True)
class Config:
    scenario: str
    window: int
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_pct: float = 0.0
    duplicate_pct: float = 0.0
    corrupt_pct: float = 0.0
    reorder_pct: float = 0.0
    rate_mbps: float = 0.0
    file_size: int = MiB
    reps: int = 3
    client_args: tuple = ()          # extra client options for this configuration only

    @property
    def mode(self):
        if self.window == 1:
            return "stop-and-wait"
        if "--selective" in self.client_args:
            return "selective"
        if "adaptive" in self.client_args:
            return "adaptive"
        return "sliding"

    def label(self):
        parts = [f"{self.scenario}", f"W{self.window}", f"{self.file_size}B", f"d{self.delay_ms:g}", f"l{self.loss_pct:g}"]
        if self.jitter_ms:
            parts.append(f"j{self.jitter_ms:g}")
        if self.mode in ("selective", "adaptive"):
            parts.append(self.mode)
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
    elif name == "s8":
        # E1: selective retransmission against the compulsory Go-Back-N window
        for extra in ((), ("--selective",)):
            out.append(Config("s8", SL, delay_ms=10 if quick else 50, loss_pct=5, file_size=fs, reps=r, client_args=extra))
        for extra in ((), ("--selective",)):
            out.append(Config("s8", SL, delay_ms=10, reorder_pct=25, file_size=fs, reps=r, client_args=extra))
    elif name == "s8b":
        # E2: adaptive timeout against the fixed timeout under delay jitter (needs Member A's --rto option)
        for extra in ((), ("--rto", "adaptive")):
            out.append(Config("s8b", SL, delay_ms=50, jitter_ms=40, file_size=fs, reps=r, client_args=extra))
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


def make_source_file(directory: Path, size: int, tag=""):
    """Random but reproducible file (fixed seed), cached on disk. tag makes a different file."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"src_{tag}{size}.bin"
    if not path.exists() or path.stat().st_size != size:
        seed = 12345 + size + (777 if tag else 0)
        path.write_bytes(random.Random(seed).randbytes(size))
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
                key = []
                for k in KEY_FIELDS:
                    value = row.get(k)
                    if k in ("scenario", "mode"):
                        key.append(value or "")
                    else:
                        key.append(nz(value if value not in (None, "") else 0))
                done.add(tuple(key))
    return done


def nz(v):
    """Normalise numbers so 5, 5.0 and '5.0' all give the same text (used in CSV and resume keys)."""
    try:
        return f"{float(v):g}"
    except (TypeError, ValueError):
        return str(v)


def key_of(cfg: Config, rep: int):
    vals = {"scenario": cfg.scenario, "mode": cfg.mode, "window": cfg.window, "delay_ms": cfg.delay_ms,
            "jitter_ms": cfg.jitter_ms, "loss_pct": cfg.loss_pct, "duplicate_pct": cfg.duplicate_pct, "corrupt_pct": cfg.corrupt_pct,
            "reorder_pct": cfg.reorder_pct, "rate_mbps": cfg.rate_mbps, "file_size": cfg.file_size, "rep": rep}
    return tuple(vals[k] if k in ("scenario", "mode") else nz(vals[k]) for k in KEY_FIELDS)


def measure_rtt(delay_ms, jitter_ms, rate_mbps, work: Path):
    """Real round-trip time of the emulated path: probe -> delay-only proxy -> echo server.
    (Probing the real server would pollute its counters, so a separate echo server is used.)"""
    from probe import run_probe
    eport, pport = free_udp_port(), free_udp_port()
    echo = prox = None
    try:
        echo = start_process([PY, "-u", str(ROOT / "testbed" / "echo_server.py"), "--port", str(eport)], work / "echo.log")
        prox = start_process([PY, "-u", str(ROOT / "testbed" / "impair_proxy.py"), "--listen", f"127.0.0.1:{pport}",
                              "--target", f"127.0.0.1:{eport}", "--delay", str(delay_ms), "--jitter", str(jitter_ms),
                              "--rate-mbps", str(rate_mbps)],
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
                "--target", f"127.0.0.1:{sport}", "--delay", str(cfg.delay_ms), "--jitter", str(cfg.jitter_ms),
                "--loss", str(cfg.loss_pct),
                "--duplicate", str(cfg.duplicate_pct), "--corrupt", str(cfg.corrupt_pct),
                "--reorder", str(cfg.reorder_pct), "--rate-mbps", str(cfg.rate_mbps),
                "--seed", str(1000 + index)]
        proxy = start_process(pcmd, cfg_dir / "proxy.log")
        if not (wait_for_text(cfg_dir / "server.log", "listening") and wait_for_text(cfg_dir / "proxy.log", "proxy ")):
            raise RuntimeError(f"server or proxy did not start (see {cfg_dir})")

        rtt = measure_rtt(cfg.delay_ms, cfg.jitter_ms, cfg.rate_mbps, cfg_dir)
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
                   "--window", str(cfg.window), "--log", str(log_path), *cfg.client_args, *args.client_args]
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
                   "jitter_ms": nz(cfg.jitter_ms), "loss_pct": nz(cfg.loss_pct), "duplicate_pct": nz(cfg.duplicate_pct), "corrupt_pct": nz(cfg.corrupt_pct),
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


# ============================================================================= Week 5 scenarios
# S5a (outage), S5b (server killed) and S7 (two clients). They need more care than a grid,
# so each one is a small function with plain loops.
S5A_FIELDS = ["scenario", "rep", "file_size", "delay_ms", "window", "baseline_s", "outage_start_s",
              "outage_len_s", "completion_s", "last_ack_before_s", "first_ack_after_s", "recovery_s",
              "recovery_ok_4s", "retransmissions", "hash_ok", "status", "timestamp"]
S5B_FIELDS = ["scenario", "rep", "file_size", "delay_ms", "window", "killed_at_s", "abort_after_kill_s",
              "abort_after_last_ack_s", "within_30s", "exit_code", "error_text", "status", "timestamp"]
S7_FIELDS = ["scenario", "rep", "run", "client", "file_size", "delay_ms", "window", "completion_s",
             "goodput_mbps", "retransmissions", "hash_ok", "slowdown_vs_single", "status", "timestamp"]


def start_stack(work: Path, delay_ms, outage=None, seed=1):
    """Fresh server + proxy. Returns (server, proxy, proxy_port, outdir)."""
    work.mkdir(parents=True, exist_ok=True)
    sport, pport = free_udp_port(), free_udp_port()
    outdir = work / "received"
    server = start_process([PY, "-u", "-m", "rft.server", "--host", "127.0.0.1", "--port", str(sport),
                            "--outdir", str(outdir), "--linger", "0.5"], work / "server.log")
    cmd = [PY, "-u", str(ROOT / "testbed" / "impair_proxy.py"), "--listen", f"127.0.0.1:{pport}",
           "--target", f"127.0.0.1:{sport}", "--delay", str(delay_ms), "--seed", str(seed)]
    if outage:
        cmd += ["--outage", f"{outage[0]},{outage[1]}"]
    proxy = start_process(cmd, work / "proxy.log")
    if not (wait_for_text(work / "server.log", "listening") and wait_for_text(work / "proxy.log", "proxy ")):
        stop_process(proxy)
        stop_process(server)
        raise RuntimeError(f"server or proxy did not start (see {work})")
    return server, proxy, pport, outdir


def stop_stack(server, proxy):
    stop_process(proxy)
    stop_process(server)


def launch_client(src, port, window, log_path):
    cmd = [PY, "-m", "rft.client", str(src), "--host", "127.0.0.1", "--port", str(port),
           "--window", str(window), "--log", str(log_path)]
    return subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def ack_times(log_path):
    """Times (seconds since the client started) at which the window advanced."""
    times = []
    try:
        with open(log_path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["event"] == "ACK_ADVANCE":
                    times.append(float(row["elapsed_seconds"]))
    except OSError:
        pass
    return times


def now_text():
    return datetime.datetime.now().isoformat(timespec="seconds")


def open_csv(path: Path, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "w", newline="", encoding="utf-8")
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    return f, writer


def results_dir(args):
    return Path(args.results_dir) if args.results_dir else ROOT / "results"


def week5_settings(args):
    quick = args.quick
    size = args.size or (262144 if quick else MiB)
    delay = 20 if quick else 50
    reps = args.reps or (1 if quick else 3)
    return size, delay, reps


def baseline_time(work, size, delay, window):
    """One clean transfer to learn how long it takes (used to pick 'about half way')."""
    src = make_source_file(work.parent / "data", size)
    server, proxy, pport, _ = start_stack(work / "baseline", delay)
    try:
        proc = launch_client(src, pport, window, work / "baseline" / "client.csv")
        out, _err = proc.communicate(timeout=600)
        seconds = parse_client_output(out)["completion_s"]
    finally:
        stop_stack(server, proxy)
    return seconds or 1.0


def run_s5a(args):
    """S5a: total outage in the middle of a transfer; does it resume, and how fast?"""
    size, delay, reps = week5_settings(args)
    outage_len = 2.0 if args.quick else 5.0
    window = 32
    out_dir = results_dir(args)
    work = out_dir / "work" / "s5a"
    f, writer = open_csv(out_dir / "s5a.csv", S5A_FIELDS)
    (out_dir / "s5_logs").mkdir(parents=True, exist_ok=True)
    src = make_source_file(work.parent / "data", size)
    src_sha = sha256_file(src)
    base = baseline_time(work, size, delay, window)
    start = max(0.3, base * 0.5)
    print(f"S5a: clean transfer takes {base:.2f} s, so the outage starts at {start:.2f} s and lasts {outage_len} s")
    for rep in range(1, reps + 1):
        server, proxy, pport, outdir = start_stack(work / f"rep{rep}", delay, outage=(start, outage_len), seed=rep)
        try:
            log_path = work / f"rep{rep}" / "client.csv"
            proc = launch_client(src, pport, window, log_path)
            stdout, stderr = proc.communicate(timeout=args.timeout_global)
            parsed = parse_client_output(stdout)
            received = outdir / src.name
            hash_ok = received.exists() and sha256_file(received) == src_sha
            status = "OK" if (proc.returncode == 0 and parsed["ok"] and hash_ok) else "FAILED: " + (stderr.strip()[:80] or "no output")
            times = ack_times(log_path)
            end = start + outage_len
            before = [t for t in times if t <= start + 0.05]
            after = [t for t in times if t > end]
            last_before = max(before) if before else ""
            first_after = min(after) if after else ""
            recovery = round(first_after - end, 3) if after else ""
            writer.writerow({"scenario": "s5a", "rep": rep, "file_size": size, "delay_ms": delay, "window": window,
                             "baseline_s": round(base, 3), "outage_start_s": round(start, 3), "outage_len_s": outage_len,
                             "completion_s": parsed["completion_s"], "last_ack_before_s": last_before,
                             "first_ack_after_s": first_after, "recovery_s": recovery,
                             "recovery_ok_4s": (recovery != "" and recovery <= 4.0),
                             "retransmissions": parsed["retransmissions"], "hash_ok": hash_ok, "status": status,
                             "timestamp": now_text()})
            f.flush()
            if log_path.exists():
                (out_dir / "s5_logs" / f"s5a_rep{rep}.csv").write_bytes(log_path.read_bytes())
            print(f"   rep {rep}: {status}  completion {parsed['completion_s']} s  recovery {recovery} s  hash_ok {hash_ok}")
        finally:
            stop_stack(server, proxy)
    f.close()


def run_s5b(args):
    """S5b: the server process is killed in the middle of a transfer; the client must give up."""
    size, delay, reps = week5_settings(args)
    window = 32
    out_dir = results_dir(args)
    work = out_dir / "work" / "s5b"
    f, writer = open_csv(out_dir / "s5b.csv", S5B_FIELDS)
    src = make_source_file(work.parent / "data", size)
    base = baseline_time(work, size, delay, window)
    kill_at = max(0.3, base * 0.5)
    print(f"S5b: the server is killed {kill_at:.2f} s after the client starts (each run takes about 25 s)")
    for rep in range(1, reps + 1):
        server, proxy, pport, _ = start_stack(work / f"rep{rep}", delay, seed=rep)
        try:
            log_path = work / f"rep{rep}" / "client.csv"
            t_start = time.monotonic()
            proc = launch_client(src, pport, window, log_path)
            time.sleep(kill_at)
            stop_process(server)                      # kill the server
            t_kill = time.monotonic()
            try:
                stdout, stderr = proc.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            t_exit = time.monotonic()
            times = ack_times(log_path)
            last_ack = max(times) if times else 0.0
            since_ack = (t_exit - t_start) - last_ack      # approximate: includes about 0.2 s of start-up
            error = (stderr.strip().splitlines() or [""])[0]
            failed_cleanly = proc.returncode == 1 and "Transfer failed" in stderr
            writer.writerow({"scenario": "s5b", "rep": rep, "file_size": size, "delay_ms": delay, "window": window,
                             "killed_at_s": round(kill_at, 3), "abort_after_kill_s": round(t_exit - t_kill, 2),
                             "abort_after_last_ack_s": round(since_ack, 2), "within_30s": since_ack <= 30,
                             "exit_code": proc.returncode, "error_text": error[:80],
                             "status": "OK" if failed_cleanly else "UNEXPECTED", "timestamp": now_text()})
            f.flush()
            print(f"   rep {rep}: exit code {proc.returncode}, gave up {since_ack:.1f} s after the last ACK: {error[:60]}")
        finally:
            stop_stack(server, proxy)
    f.close()


def run_s7(args):
    """S7: one transfer alone, then two different files at the same time."""
    size, delay, reps = week5_settings(args)
    window = 32
    out_dir = results_dir(args)
    work = out_dir / "work" / "s7"
    f, writer = open_csv(out_dir / "s7.csv", S7_FIELDS)
    src_a = make_source_file(work.parent / "data", size)
    src_b = make_source_file(work.parent / "data", size, tag="b")
    sha = {"A": sha256_file(src_a), "B": sha256_file(src_b)}
    paths = {"A": src_a, "B": src_b}
    for rep in range(1, reps + 1):
        server, proxy, pport, outdir = start_stack(work / f"rep{rep}", delay, seed=rep)
        try:
            runs = [("single", ["A"]), ("concurrent", ["A", "B"])]
            single_time = None
            for run_name, clients in runs:
                procs = {}
                for c in clients:
                    procs[c] = launch_client(paths[c], pport, window, work / f"rep{rep}" / f"{run_name}_{c}.csv")
                for c in clients:
                    stdout, stderr = procs[c].communicate(timeout=args.timeout_global)
                    parsed = parse_client_output(stdout)
                    received = outdir / paths[c].name
                    hash_ok = received.exists() and sha256_file(received) == sha[c]
                    status = "OK" if (procs[c].returncode == 0 and parsed["ok"] and hash_ok) else "FAILED"
                    if run_name == "single":
                        single_time = parsed["completion_s"]
                    slowdown = ""
                    if run_name == "concurrent" and single_time and parsed["completion_s"]:
                        slowdown = round(parsed["completion_s"] / single_time, 2)
                    writer.writerow({"scenario": "s7", "rep": rep, "run": run_name, "client": c, "file_size": size,
                                     "delay_ms": delay, "window": window, "completion_s": parsed["completion_s"],
                                     "goodput_mbps": parsed["goodput_mbps"], "retransmissions": parsed["retransmissions"],
                                     "hash_ok": hash_ok, "slowdown_vs_single": slowdown, "status": status,
                                     "timestamp": now_text()})
                    f.flush()
                    print(f"   rep {rep} {run_name} {c}: {status}  {parsed['completion_s']} s  hash_ok {hash_ok}")
                    if received.exists():
                        os.remove(received)
        finally:
            stop_stack(server, proxy)
    f.close()


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
    ap.add_argument("--scenario", default=None,
                    help="calibrate, s1, s2, s3, o2, s4, s6, s8, s8b, s5a, s5b, s5 (=s5a+s5b), s7, core or week5 (=s5a+s5b+s7)")
    ap.add_argument("--reps", type=int, default=None, help="repetitions per configuration (default 3; o2 uses 10)")
    ap.add_argument("--quick", action="store_true", help="small files and a reduced grid, for a smoke test")
    ap.add_argument("--size", type=int, default=None, help="override the file size in bytes")
    ap.add_argument("--resume", action="store_true", help="append to the CSV and skip runs already in it")
    ap.add_argument("--capture", action="store_true", help="tshark capture of the first run of each configuration")
    ap.add_argument("--timeout", type=float, default=900, help="per-run limit in seconds")
    ap.add_argument("--out", default=None, help="output CSV (default results/<scenario>.csv)")
    ap.add_argument("--client-args", default="", help="extra client options, e.g. \"--chunk-size 1400\"")
    ap.add_argument("--results-dir", default=None, help="where S5 and S7 write their files (default results)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and a rough time estimate")
    ap.add_argument("--merge", action="store_true", help="combine results/*.csv into results/all_results.csv")
    args = ap.parse_args(argv)
    args.client_args = shlex.split(args.client_args)
    if args.merge:
        merge_results(ROOT / "results")
        return 0
    if not args.scenario:
        ap.error("--scenario is required (or use --merge)")
    args.timeout_global = args.timeout
    special = {"s5a": run_s5a, "s5b": run_s5b, "s7": run_s7}
    if args.scenario in ("s5", "week5"):
        order = ["s5a", "s5b", "s7"] if args.scenario == "week5" else ["s5a", "s5b"]
        if args.dry_run:
            print("Week 5 special runs: " + ", ".join(order) + " (S5b alone takes about 25 s per repetition)")
            return 0
        for n in order:
            special[n](args)
        return 0
    if args.scenario in special:
        if args.dry_run:
            print(f"{args.scenario}: special run, see the docstring of run_{args.scenario}")
            return 0
        special[args.scenario](args)
        return 0
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
