"""Count DATA retransmissions in a Wireshark/tshark capture (Member B, Week 4).

Plan check (section 7.4): the retransmission count seen in the capture must equal
the client's own counter within 1 %.

How it works: on the client -> proxy leg every DATA packet the client sends is
visible. A chunk sent N times appears N times with the same sequence number, so
    retransmissions = (DATA packets seen) - (distinct DATA sequence numbers).

Usage (needs tshark, which installs with Wireshark):
    python experiments\\pcap_check.py results\\captures\\s2_xxx.pcapng --port 5006 --client-count 33
"""
import argparse
import os
import shutil
import subprocess
import sys

DATA_TYPE = 3
WIN_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


def find_tshark():
    return shutil.which("tshark") or (WIN_TSHARK if os.path.exists(WIN_TSHARK) else None)


def count_retransmissions(hex_lines):
    """hex_lines: one hex string of the UDP payload per packet (tshark data.data field).

    Returns (data_packets, distinct_sequences, retransmissions). Packets that are
    too short, not DATA, or not our version are ignored.
    """
    total, seen = 0, set()
    for line in hex_lines:
        h = line.strip().replace(":", "")
        if len(h) < 32:                      # header is 16 bytes = 32 hex digits
            continue
        try:
            raw = bytes.fromhex(h[:32])
        except ValueError:
            continue
        version, ptype = raw[0], raw[1]
        if version != 1 or ptype != DATA_TYPE:
            continue
        tid = int.from_bytes(raw[4:8], "big")
        seq = int.from_bytes(raw[8:12], "big")
        total += 1
        seen.add((tid, seq))
    return total, len(seen), total - len(seen)


def within_one_percent(pcap_count, client_count):
    """True if the two counters agree within 1 % (or differ by at most 1 packet)."""
    if abs(pcap_count - client_count) <= 1:
        return True
    return abs(pcap_count - client_count) <= 0.01 * max(pcap_count, client_count)


def read_capture(path, dst_port):
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("tshark not found (install Wireshark, or add it to PATH)")
    out = subprocess.run(
        [tshark, "-r", str(path), "-Y", f"udp.dstport == {dst_port}", "-T", "fields", "-e", "data.data"],
        capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "tshark failed")
    return out.stdout.splitlines()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Count retransmissions in a capture")
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=5006, help="port the client sends to (proxy port)")
    ap.add_argument("--client-count", type=int, default=None, help="client's own retransmission counter")
    a = ap.parse_args(argv)
    total, distinct, retrans = count_retransmissions(read_capture(a.pcap, a.port))
    print(f"DATA packets {total}, distinct sequence numbers {distinct}, retransmissions {retrans}")
    if a.client_count is not None:
        ok = within_one_percent(retrans, a.client_count)
        print(f"client counter {a.client_count}: {'MATCH (within 1 %)' if ok else 'MISMATCH'}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
