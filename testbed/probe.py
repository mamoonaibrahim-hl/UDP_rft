"""UDP probe: the Windows version of the Section 6 feasibility checks.

Sends N numbered datagrams to an echo server (directly or through
impair_proxy.py) and reports loss, RTT, duplicates, reordering, corruption.

    python testbed\\probe.py --port 5006 --count 100
    python testbed\\probe.py --port 5006 --count 1000 --interval 0.002
"""
import argparse
import select
import socket
import statistics
import struct
import sys
import time


def _disable_udp_connreset(sock):
    if sys.platform == "win32":
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except (AttributeError, OSError, ValueError):
            pass


def make_payload(seq: int, size: int) -> bytes:
    head = struct.pack("!I", seq)
    filler = bytes((seq + i) & 0xFF for i in range(max(0, size - 4)))
    return head + filler


def run_probe(host="127.0.0.1", port=5006, count=100, size=64, interval=0.01, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    _disable_udp_connreset(sock)
    sent_at, rtts, seen = {}, [], set()
    dup = ooo = corrupt = 0
    highest = -1
    sent = 0
    next_send = time.monotonic()
    last_send = next_send

    def drain():
        nonlocal dup, ooo, corrupt, highest
        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except (BlockingIOError, ConnectionResetError):
                return
            now = time.monotonic()
            if len(data) < 4:
                corrupt += 1
                continue
            seq = struct.unpack_from("!I", data)[0]
            if seq not in sent_at or data != make_payload(seq, size):
                corrupt += 1
                continue
            if seq in seen:
                dup += 1
                continue
            seen.add(seq)
            rtts.append((now - sent_at[seq]) * 1000)
            if seq < highest:
                ooo += 1
            highest = max(highest, seq)

    while True:
        now = time.monotonic()
        if sent < count and now >= next_send:
            sent_at[sent] = now
            sock.sendto(make_payload(sent, size), (host, port))
            sent += 1
            last_send = now
            next_send += interval
        elif sent >= count and now - last_send > timeout:
            break
        select.select([sock], [], [], 0.002)
        drain()
    sock.close()

    got = len(seen)
    return {
        "sent": count, "received": got, "lost": count - got,
        "loss_pct": 100.0 * (count - got) / count if count else 0.0,
        "duplicates": dup, "out_of_order": ooo, "corrupted": corrupt,
        "rtt_min_ms": min(rtts) if rtts else None,
        "rtt_avg_ms": statistics.fmean(rtts) if rtts else None,
        "rtt_max_ms": max(rtts) if rtts else None,
        "rtt_std_ms": statistics.pstdev(rtts) if len(rtts) > 1 else 0.0,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="UDP probe")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5006)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--size", type=int, default=64, help="datagram size in bytes (>= 4)")
    ap.add_argument("--interval", type=float, default=0.01, help="seconds between sends")
    ap.add_argument("--timeout", type=float, default=2.0, help="wait for stragglers, seconds")
    a = ap.parse_args(argv)
    r = run_probe(a.host, a.port, a.count, a.size, a.interval, a.timeout)
    print(f"sent {r['sent']}  received {r['received']}  lost {r['lost']} ({r['loss_pct']:.1f}%)")
    print(f"duplicates {r['duplicates']}  out-of-order {r['out_of_order']}  corrupted {r['corrupted']}")
    if r["rtt_avg_ms"] is not None:
        print(f"RTT ms: min {r['rtt_min_ms']:.1f}  avg {r['rtt_avg_ms']:.1f}  "
              f"max {r['rtt_max_ms']:.1f}  std {r['rtt_std_ms']:.1f}")
    else:
        print("no replies received")


if __name__ == "__main__":
    main()
