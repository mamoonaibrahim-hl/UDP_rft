"""UDP echo server for the Windows test bed (Member B, Week 1).

Replaces "the other namespace" from the Linux plan: it just sends every
datagram straight back, so probe.py can measure delay / loss / duplication
through impair_proxy.py.

    python testbed\\echo_server.py --host 127.0.0.1 --port 5005
"""
import argparse
import selectors
import socket
import sys
import threading
from collections import Counter


def _disable_udp_connreset(sock):
    if sys.platform == "win32":
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except (AttributeError, OSError, ValueError):
            pass


class EchoServer:
    def __init__(self, host="127.0.0.1", port=5005):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.setblocking(False)
        _disable_udp_connreset(self.sock)
        self.stats = Counter()
        self._stop = threading.Event()

    @property
    def address(self):
        return self.sock.getsockname()

    def serve_forever(self):
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ)
        try:
            while not self._stop.is_set():
                if not sel.select(timeout=0.1):
                    continue
                while True:
                    try:
                        data, addr = self.sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    except ConnectionResetError:
                        continue
                    self.stats["packets"] += 1
                    self.stats["bytes"] += len(data)
                    self.sock.sendto(data, addr)
        finally:
            sel.close()
            self.sock.close()

    def stop(self):
        self._stop.set()


def main(argv=None):
    ap = argparse.ArgumentParser(description="UDP echo server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5005)
    a = ap.parse_args(argv)
    srv = EchoServer(a.host, a.port)
    print(f"echo server listening on {srv.address[0]}:{srv.address[1]} (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\nechoed {srv.stats['packets']} packets, {srv.stats['bytes']} bytes")


if __name__ == "__main__":
    main()
