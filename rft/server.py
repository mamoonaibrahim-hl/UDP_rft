"""Receiver / server for Reliable File Transfer over UDP (Member B, Week 2).

Implements spec features F2 (session setup), F7 (duplicates / out-of-order),
F8 (SHA-256 verification), F9 (teardown + linger), F10 (concurrent sessions)
and F12 (error handling) with a single-threaded selector loop.

Run (from the repo root, e.g. in PowerShell):
    python -m rft.server --host 127.0.0.1 --port 5005 --outdir received
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import posixpath
import selectors
import socket
import struct
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from . import packet as P
from .sack import SACK_RANGE, make_sack

log = logging.getLogger("rft.server")

DEFAULT_PORT = 5005
LINGER_S = 6.0          # keep finished session so a lost FIN-ACK can be re-sent
INACTIVITY_S = 30.0     # free state if the client goes silent
MAX_CHUNK = 1400
MAX_FILE_SIZE = 2 ** 32  # sanity cap (sequence numbers are 32-bit)

STATUS_OK, STATUS_HASH_MISMATCH, STATUS_SIZE_MISMATCH = 0, 1, 2
ERR_BAD_SYN, ERR_NO_SESSION, ERR_IO = 1, 2, 3

# SYN payload: file size (8) | chunk size (2) | sha256 (32) | name length (2) | name (utf-8)
SYN_FMT = "!QH32sH"
SYN_FIXED = struct.calcsize(SYN_FMT)  # 44

RECEIVING, LINGER = "RECEIVING", "LINGER"

CSV_FIELDS = ["time", "client", "transfer_id", "file", "status", "bytes", "chunks",
              "duplicates", "out_of_order", "bad_length", "seconds", "corrupt_dropped_total"]


def parse_syn_payload(payload: bytes):
    """Return (file_size, chunk_size, sha256_digest, file_name) or raise ValueError."""
    if len(payload) < SYN_FIXED:
        raise ValueError("SYN too short")
    size, chunk, sha, nlen = struct.unpack_from(SYN_FMT, payload)
    raw = payload[SYN_FIXED:SYN_FIXED + nlen]
    if len(raw) != nlen:
        raise ValueError("file name truncated")
    return size, chunk, sha, raw.decode("utf-8")


def parse_syn_options(payload: bytes) -> int:
    """Optional byte after the file name. Bit 0 = the client wants selective ACKs (extension E1)."""
    if len(payload) < SYN_FIXED:
        return 0
    name_length = struct.unpack_from("!H", payload, SYN_FIXED - 2)[0]
    position = SYN_FIXED + name_length
    if len(payload) > position:
        return payload[position]
    return 0


def safe_name(name: str) -> str:
    """Strip any directory part and characters Windows cannot store."""
    name = posixpath.basename(name.replace("\\", "/")).strip()
    name = "".join("_" if (c in '<>:"|?*' or ord(c) < 32) else c for c in name)
    if name in ("", ".", ".."):
        raise ValueError("bad file name")
    return name


def _disable_udp_connreset(sock: socket.socket) -> None:
    """Windows raises ConnectionResetError on recvfrom after an ICMP 'port
    unreachable'. Turn that behaviour off (no-op on Linux/macOS)."""
    if sys.platform == "win32":
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except (AttributeError, OSError, ValueError):
            pass


@dataclass
class Session:
    addr: tuple
    tid: int
    name: str
    size: int
    chunk: int
    sha: bytes
    total_chunks: int
    part_path: str
    final_path: str
    fh: object
    hasher: object
    started: float
    last_activity: float
    expected: int = 0
    written: int = 0
    state: str = RECEIVING
    linger_until: float = 0.0
    status: int | None = None
    duplicates: int = 0
    out_of_order: int = 0
    bad_len: int = 0
    early_fin: int = 0
    selective: bool = False                       # extension E1: buffer out-of-order chunks
    buffer: dict = field(default_factory=dict)    # chunk number -> payload waiting for its turn

    def expected_len(self, seq: int) -> int:
        if seq < self.total_chunks - 1:
            return self.chunk
        return self.size - (self.total_chunks - 1) * self.chunk


class Server:
    def __init__(self, host="127.0.0.1", port=DEFAULT_PORT, outdir="received",
                 linger=LINGER_S, inactivity=INACTIVITY_S, stats_csv=None):
        self.stats_csv = stats_csv          # optional per-session CSV for experiments
        self.outdir = outdir
        self.linger = linger
        self.inactivity = inactivity
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self.sock.bind((host, port))
        self.sock.setblocking(False)
        _disable_udp_connreset(self.sock)
        self.sessions: dict[tuple, Session] = {}
        self.stats = Counter()
        self.finished: list[dict] = []   # one summary dict per completed/aborted session
        self._stop = threading.Event()
        os.makedirs(outdir, exist_ok=True)

    @property
    def address(self):
        return self.sock.getsockname()

    # ------------------------------------------------------------------ loop
    def serve_forever(self):
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ)
        log.info("listening on %s:%d, saving to %s", *self.address, self.outdir)
        try:
            while not self._stop.is_set():
                if sel.select(timeout=0.1):
                    self._drain()
                self._reap(time.monotonic())
        finally:
            for s in list(self.sessions.values()):
                self._abort(s, "server stopped")
            sel.close()
            self.sock.close()

    def stop(self):
        self._stop.set()

    def _drain(self):
        for _ in range(512):  # bounded so timers still run under heavy load
            try:
                data, addr = self.sock.recvfrom(2048)
            except BlockingIOError:
                return
            except ConnectionResetError:
                continue
            except OSError:
                return
            self.handle_datagram(data, addr)

    # -------------------------------------------------------------- dispatch
    def handle_datagram(self, data: bytes, addr):
        try:
            ptype, tid, seq, payload = P.decode(data)
        except P.PacketError:
            self.stats["corrupt_dropped"] += 1
            return
        now = time.monotonic()
        if ptype == P.SYN:
            self._on_syn(addr, tid, payload, now)
        elif ptype == P.DATA:
            self._on_data(addr, tid, seq, payload, now)
        elif ptype == P.FIN:
            self._on_fin(addr, tid, seq, now)
        elif ptype == P.ERROR:
            s = self.sessions.get((addr, tid))
            if s:
                self._abort(s, "client sent ERROR")
        # SYN-ACK / ACK / FIN-ACK are never valid at the server: ignore.

    def _send(self, addr, ptype, tid, seq=0, payload=b""):
        try:
            self.sock.sendto(P.encode(ptype, tid, seq, payload), addr)
        except OSError:
            pass

    def _error(self, addr, tid, code, text):
        self._send(addr, P.ERROR, tid, 0, bytes([code]) + text.encode()[:100])

    # ------------------------------------------------------------------- SYN
    def _on_syn(self, addr, tid, payload, now):
        s = self.sessions.get((addr, tid))
        if s:                                  # duplicate SYN -> same SYN-ACK
            s.last_activity = now
            self._send(addr, P.SYN_ACK, tid)
            return
        try:
            size, chunk, sha, name = parse_syn_payload(payload)
            if not 1 <= chunk <= MAX_CHUNK or size > MAX_FILE_SIZE:
                raise ValueError("bad size / chunk size")
            name = safe_name(name)
        except ValueError:
            self.stats["bad_syn"] += 1
            self._error(addr, tid, ERR_BAD_SYN, "bad SYN")
            return
        final = os.path.join(self.outdir, name)
        part = os.path.join(self.outdir, f"{name}.{tid:08x}.part")
        try:
            fh = open(part, "wb")
        except OSError:
            self._error(addr, tid, ERR_IO, "cannot create file")
            return
        total = (size + chunk - 1) // chunk
        new_session = Session(
            addr, tid, name, size, chunk, sha, total, part, final, fh,
            hashlib.sha256(), started=now, last_activity=now)
        new_session.selective = bool(parse_syn_options(payload) & 1)
        self.sessions[(addr, tid)] = new_session
        log.info("SYN  %s tid=%08x name=%s size=%d chunks=%d", addr, tid, name, size, total)
        self._send(addr, P.SYN_ACK, tid)

    # ------------------------------------------------------------------ DATA
    def _on_data(self, addr, tid, seq, payload, now):
        s = self.sessions.get((addr, tid))
        if s is None:
            self.stats["unknown_session"] += 1
            self._error(addr, tid, ERR_NO_SESSION, "no such session")
            return
        s.last_activity = now
        if s.state != RECEIVING:               # already complete: just re-ACK
            s.duplicates += 1
            self._send(addr, P.ACK, tid, s.expected)
            return
        if s.selective:
            self._data_selective(s, addr, tid, seq, payload)
            return
        if seq == s.expected:
            if seq >= s.total_chunks or len(payload) != s.expected_len(seq):
                s.bad_len += 1                 # inconsistent length: drop, no ACK
                return
            try:
                s.fh.write(payload)
            except OSError:
                self._error(addr, tid, ERR_IO, "disk write failed")
                self._abort(s, "disk write failed")
                return
            s.hasher.update(payload)
            s.written += len(payload)
            s.expected += 1
        elif seq < s.expected:
            s.duplicates += 1
        else:
            s.out_of_order += 1                # discard (go-back-N receiver)
        self._send(addr, P.ACK, tid, s.expected)

    def _write_chunk(self, s, payload):
        """Write one in-order chunk (selective sessions). Returns False if the disk failed."""
        try:
            s.fh.write(payload)
        except OSError:
            return False
        s.hasher.update(payload)
        s.written += len(payload)
        s.expected += 1
        return True

    def _data_selective(self, s, addr, tid, seq, payload):
        """Extension E1: keep chunks that arrive early and tell the sender which ones we hold."""
        if seq < s.expected or seq in s.buffer:
            s.duplicates += 1
        elif seq >= s.total_chunks or seq >= s.expected + SACK_RANGE:
            s.out_of_order += 1                       # too far ahead: ignore it
        elif len(payload) != s.expected_len(seq):
            s.bad_len += 1
            return                                    # wrong length: drop, no ACK
        elif seq == s.expected:
            ok = self._write_chunk(s, payload)
            while ok and s.expected in s.buffer:      # now the buffered chunks can follow
                ok = self._write_chunk(s, s.buffer.pop(s.expected))
            if not ok:
                self._error(addr, tid, ERR_IO, "disk write failed")
                self._abort(s, "disk write failed")
                return
        else:
            s.buffer[seq] = payload
            s.out_of_order += 1
        self._send(addr, P.ACK, tid, s.expected, make_sack(s.expected, s.buffer))

    # ------------------------------------------------------------------- FIN
    def _on_fin(self, addr, tid, seq, now):
        s = self.sessions.get((addr, tid))
        if s is None:
            self.stats["unknown_session"] += 1
            self._error(addr, tid, ERR_NO_SESSION, "no such session")
            return
        s.last_activity = now
        if s.state == LINGER:                  # retransmitted FIN -> same FIN-ACK
            self._send(addr, P.FIN_ACK, tid, s.total_chunks, bytes([s.status]))
            return
        if s.expected != s.total_chunks or seq != s.total_chunks:
            s.early_fin += 1                   # not everything received: stay silent
            return
        s.fh.close()
        if s.written != s.size:
            status = STATUS_SIZE_MISMATCH
        elif s.hasher.digest() != s.sha:
            status = STATUS_HASH_MISMATCH
        else:
            status = STATUS_OK
        if status == STATUS_OK:
            os.replace(s.part_path, s.final_path)
        else:
            os.replace(s.part_path, s.part_path[:-5] + ".bad")
        s.status, s.state, s.linger_until = status, LINGER, now + self.linger
        self._record(self._summary(s, status))
        log.info("FIN  %s tid=%08x status=%d dup=%d ooo=%d", addr, tid, status,
                 s.duplicates, s.out_of_order)
        self._send(addr, P.FIN_ACK, tid, s.total_chunks, bytes([status]))

    # --------------------------------------------------------------- cleanup
    def _summary(self, s: Session, status):
        return {"addr": s.addr, "tid": s.tid, "name": s.name, "status": status,
                "bytes": s.written, "chunks": s.expected, "duplicates": s.duplicates,
                "out_of_order": s.out_of_order, "bad_len": s.bad_len,
                "seconds": time.monotonic() - s.started}

    def _record(self, summary: dict):
        """Keep the summary in memory and, if --stats-csv is set, append a CSV row."""
        self.finished.append(summary)
        if not self.stats_csv:
            return
        row = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "client": f"{summary['addr'][0]}:{summary['addr'][1]}",
            "transfer_id": f"{summary['tid']:08x}",
            "file": summary["name"],
            "status": summary["status"],
            "bytes": summary["bytes"],
            "chunks": summary["chunks"],
            "duplicates": summary["duplicates"],
            "out_of_order": summary["out_of_order"],
            "bad_length": summary["bad_len"],
            "seconds": f"{summary['seconds']:.3f}",
            "corrupt_dropped_total": self.stats["corrupt_dropped"],
        }
        try:
            new = not os.path.exists(self.stats_csv) or os.path.getsize(self.stats_csv) == 0
            with open(self.stats_csv, "a", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                if new:
                    w.writeheader()
                w.writerow(row)
        except OSError:
            log.warning("cannot write stats CSV %s", self.stats_csv)

    def _abort(self, s: Session, reason: str):
        try:
            if not s.fh.closed:
                s.fh.close()
            if s.state == RECEIVING and os.path.exists(s.part_path):
                os.remove(s.part_path)
        except OSError:
            pass
        if s.state == RECEIVING:
            self._record(self._summary(s, "ABORTED: " + reason))
            log.warning("ABORT %s tid=%08x: %s", s.addr, s.tid, reason)
        self.sessions.pop((s.addr, s.tid), None)

    def _reap(self, now):
        for s in list(self.sessions.values()):
            if s.state == LINGER and now >= s.linger_until:
                self.sessions.pop((s.addr, s.tid), None)
            elif s.state == RECEIVING and now - s.last_activity > self.inactivity:
                self._abort(s, "inactivity timeout")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reliable file transfer over UDP: server")
    ap.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 to accept other PCs")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--outdir", default="received")
    ap.add_argument("--linger", type=float, default=LINGER_S)
    ap.add_argument("--inactivity", type=float, default=INACTIVITY_S)
    ap.add_argument("--stats-csv", default=None, help="append one row per finished session")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    srv = Server(a.host, a.port, a.outdir, a.linger, a.inactivity, a.stats_csv)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("stopped; stats=%s", dict(srv.stats))


if __name__ == "__main__":
    main()
