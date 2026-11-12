"""User-space network impairment proxy (Member B, Week 1).

Windows replacement for `tc netem` (risk R1 in the Submission 1 report).
Sits between the client and the server:

    client --> proxy (listen) --> server
    client <-- proxy          <-- server

Every datagram, in BOTH directions, independently suffers the configured
loss, delay (+jitter), duplication, corruption, reordering, rate limit and
an optional total outage - the same knobs as netem.

    python testbed\\impair_proxy.py --listen 127.0.0.1:5006 --target 127.0.0.1:5005 ^
        --delay 50 --loss 5 --seed 1

Units follow netem: --delay/--jitter in ms, --loss/--duplicate/--corrupt/
--reorder in percent. With --delay D the RTT becomes about 2*D (D each way).
"""
from __future__ import annotations

import argparse
import heapq
import random
import selectors
import socket
import sys
import threading
import time
from collections import Counter


def _disable_udp_connreset(sock):
    if sys.platform == "win32":
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except (AttributeError, OSError, ValueError):
            pass


class Impairment:
    """Decides what happens to ONE datagram. Pure logic -> easy to unit-test.

    apply(data, now) returns a list of (delay_seconds, bytes):
      []                      packet lost
      [(d, data)]             delivered after d seconds
      [(d1, data), (d2, x)]   duplicated (and/or corrupted copies)
    """

    def __init__(self, loss=0.0, delay_ms=0.0, jitter_ms=0.0, duplicate=0.0,
                 corrupt=0.0, reorder=0.0, outage=None, seed=None):
        self.loss, self.duplicate = loss / 100, duplicate / 100
        self.corrupt, self.reorder = corrupt / 100, reorder / 100
        self.delay, self.jitter = delay_ms / 1000, jitter_ms / 1000
        self.outage = outage            # (start_s, length_s) after the first packet
        self.rng = random.Random(seed)
        self.stats = Counter()
        self._t0 = None

    def in_outage(self, now):
        if self.outage is None or self._t0 is None:
            return False
        start, length = self.outage
        return self._t0 + start <= now < self._t0 + start + length

    def apply(self, data: bytes, now: float):
        if self._t0 is None:
            self._t0 = now
        self.stats["received"] += 1
        if self.in_outage(now):
            self.stats["outage_dropped"] += 1
            return []
        if self.rng.random() < self.loss:
            self.stats["lost"] += 1
            return []
        copies = 1
        if self.rng.random() < self.duplicate:
            copies = 2
            self.stats["duplicated"] += 1
        out = []
        for _ in range(copies):
            payload = data
            if data and self.rng.random() < self.corrupt:
                b = bytearray(data)
                b[self.rng.randrange(len(b))] ^= self.rng.randrange(1, 256)
                payload = bytes(b)
                self.stats["corrupted"] += 1
            d = self.delay
            if self.jitter:
                d = max(0.0, d + self.rng.uniform(-self.jitter, self.jitter))
            if self.reorder and self.delay and self.rng.random() < self.reorder:
                d = 0.0                    # netem style: this one overtakes the delayed rest
                self.stats["reordered"] += 1
            out.append((d, payload))
        self.stats["forwarded"] += len(out)
        return out


class Proxy:
    def __init__(self, listen, target, c2s: Impairment, s2c: Impairment, rate_mbps=0.0):
        self.target = target
        self.imp = {"c2s": c2s, "s2c": s2c}
        self.rate_bps = rate_mbps * 1e6
        self._link_free = {"c2s": 0.0, "s2c": 0.0}
        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.lsock.bind(listen)
        self.lsock.setblocking(False)
        _disable_udp_connreset(self.lsock)
        self.upstream = {}              # client addr -> socket towards the server
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.lsock, selectors.EVENT_READ, None)
        self.heap = []                  # (release_time, counter, direction, client_addr, bytes)
        self._n = 0
        self._stop = threading.Event()

    @property
    def address(self):
        return self.lsock.getsockname()

    def stop(self):
        self._stop.set()

    def _upstream_for(self, addr):
        s = self.upstream.get(addr)
        if s is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((self.lsock.getsockname()[0], 0))
            s.setblocking(False)
            _disable_udp_connreset(s)
            self.sel.register(s, selectors.EVENT_READ, addr)
            self.upstream[addr] = s
        return s

    def _schedule(self, direction, addr, data):
        now = time.monotonic()
        for delay, payload in self.imp[direction].apply(data, now):
            release = now + delay
            if self.rate_bps:           # serialisation delay on a shared link
                release = max(release, self._link_free[direction])
                self._link_free[direction] = release + len(payload) * 8 / self.rate_bps
            self._n += 1
            heapq.heappush(self.heap, (release, self._n, direction, addr, payload))

    def serve_forever(self):
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                wait = 0.05 if not self.heap else max(0.0, min(0.05, self.heap[0][0] - now))
                for key, _ in self.sel.select(timeout=wait):
                    self._read(key.fileobj, key.data)
                self._flush(time.monotonic())
        finally:
            for s in list(self.upstream.values()):
                self.sel.unregister(s)
                s.close()
            self.sel.close()
            self.lsock.close()

    def _read(self, sock, client_addr):
        for _ in range(512):
            try:
                data, src = sock.recvfrom(65535)
            except (BlockingIOError, ConnectionResetError):
                return
            if client_addr is None:     # arrived on the listening socket: client -> server
                self._upstream_for(src)
                self._schedule("c2s", src, data)
            else:                       # arrived from the server for this client
                self._schedule("s2c", client_addr, data)

    def _flush(self, now):
        while self.heap and self.heap[0][0] <= now:
            _, _, direction, addr, payload = heapq.heappop(self.heap)
            try:
                if direction == "c2s":
                    self.upstream[addr].sendto(payload, self.target)
                else:
                    self.lsock.sendto(payload, addr)
            except OSError:
                pass

    def report(self):
        lines = []
        for d in ("c2s", "s2c"):
            st = self.imp[d].stats
            lines.append(f"{d}: " + ", ".join(f"{k}={v}" for k, v in sorted(st.items())))
        return "\n".join(lines)


def _hostport(text):
    host, _, port = text.rpartition(":")
    return (host or "127.0.0.1", int(port))


def main(argv=None):
    ap = argparse.ArgumentParser(description="UDP impairment proxy (netem substitute)")
    ap.add_argument("--listen", default="127.0.0.1:5006", help="address the client sends to")
    ap.add_argument("--target", default="127.0.0.1:5005", help="real server address")
    ap.add_argument("--delay", type=float, default=0, help="one-way delay per direction, ms")
    ap.add_argument("--jitter", type=float, default=0, help="+/- jitter, ms")
    ap.add_argument("--loss", type=float, default=0, help="loss per direction, percent")
    ap.add_argument("--duplicate", type=float, default=0, help="percent")
    ap.add_argument("--corrupt", type=float, default=0, help="percent")
    ap.add_argument("--reorder", type=float, default=0, help="percent (needs --delay)")
    ap.add_argument("--rate-mbps", type=float, default=0, help="link rate per direction, 0 = unlimited")
    ap.add_argument("--outage", default=None, metavar="START,LEN",
                    help="total blackout, seconds after first packet, e.g. 3,5")
    ap.add_argument("--seed", type=int, default=None, help="make a run reproducible")
    a = ap.parse_args(argv)
    outage = tuple(float(x) for x in a.outage.split(",")) if a.outage else None

    def make(offset):
        return Impairment(a.loss, a.delay, a.jitter, a.duplicate, a.corrupt, a.reorder,
                          outage, None if a.seed is None else a.seed + offset)

    proxy = Proxy(_hostport(a.listen), _hostport(a.target), make(0), make(1), a.rate_mbps)
    print(f"proxy {proxy.address[0]}:{proxy.address[1]} -> {a.target}  "
          f"delay={a.delay}ms loss={a.loss}% dup={a.duplicate}% corrupt={a.corrupt}% "
          f"reorder={a.reorder}% rate={a.rate_mbps or 'inf'}Mbps outage={outage}")
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        print("\n" + proxy.report())


if __name__ == "__main__":
    main()
