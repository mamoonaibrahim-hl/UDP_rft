"""Reliable UDP client with stop-and-wait and Go-Back-N."""

import argparse
import csv
import hashlib
import secrets
import socket
import struct
import sys
import time
from pathlib import Path

from rft import packet as P


SYN_FMT = struct.Struct("!QH32sH")

BASE_RTO = 0.3
MAX_RTO = 3.0

# Initial SYN plus five retries.
SYN_ATTEMPTS = 6

DATA_ATTEMPTS = 10
FIN_ATTEMPTS = 10

STATUS_NAMES = {
    0: "OK",
    1: "HASH_MISMATCH",
    2: "SIZE_MISMATCH",
}

P_NAMES = {
    P.SYN: "SYN",
    P.SYN_ACK: "SYN_ACK",
    P.DATA: "DATA",
    P.ACK: "ACK",
    P.FIN: "FIN",
    P.FIN_ACK: "FIN_ACK",
    P.ERROR: "ERROR",
}


class TransferError(Exception):
    """Raised when a transfer cannot complete."""


class Client:
    selective = False        # E1: the SelectiveClient subclass sets this to True

    def syn_options(self):
        return b""          # E1: extra bytes after the file name in the SYN

    def __init__(
        self, sock, transfer_id, file_size, writer, window=1
    ):
        self.sock = sock
        self.transfer_id = transfer_id
        self.file_size = file_size
        self.writer = writer
        self.window = window

        self.started = time.monotonic()
        self.last_progress = self.started
        self.acked_bytes = 0
        self.retransmissions = 0
        self.base = 0
        self.next_seq = 0

    def log(self, event, seq):
        elapsed = time.monotonic() - self.started

        self.writer.writerow([
            f"{elapsed:.6f}",
            event,
            seq,
            self.acked_bytes,
            self.window,
            self.base,
            self.next_seq,
            self.retransmissions,
        ])

    def progress(self, force=False):
        now = time.monotonic()

        if not force and now - self.last_progress < 1.0:
            return

        elapsed = max(now - self.started, 0.000001)

        if self.file_size:
            percent = 100 * self.acked_bytes / self.file_size
        else:
            percent = 100.0

        goodput = self.acked_bytes * 8 / elapsed

        print(
            f"Progress: {percent:.1f}% | "
            f"Goodput: {goodput / 1_000_000:.3f} Mbps | "
            f"DATA retransmissions: {self.retransmissions}",
            flush=True,
        )

        self.last_progress = now

    def send_packet(self, encoded, seq):
        """Treat a Windows UDP reset as a failed send attempt.

        The normal timer and retry limit handle recovery.
        Other socket errors are allowed to propagate.
        """
        try:
            self.sock.send(encoded)
        except ConnectionResetError:
            self.log("CONNECTION_RESET_SEND", seq)

    def wait_for(self, expected_type, expected_seq, timeout):
        """Wait for a valid reply without resetting the deadline."""
        deadline = time.monotonic() + timeout

        while True:
            self.progress()

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                return None

            self.sock.settimeout(min(remaining, 0.2))

            try:
                raw = self.sock.recv(65535)
            except socket.timeout:
                continue
            except ConnectionResetError:
                # Windows may report an ICMP port-unreachable
                # as WinError 10054. Keep the original deadline.
                self.log("CONNECTION_RESET_RECV", -1)
                continue

            try:
                packet = P.decode(raw)
            except P.PacketError:
                self.log("DROP_INVALID", -1)
                continue

            if packet.transfer_id != self.transfer_id:
                continue

            if packet.ptype == P.ERROR:
                if not packet.payload:
                    raise TransferError(
                        "server sent an empty ERROR packet"
                    )

                code = packet.payload[0]
                message = packet.payload[1:].decode(
                    "utf-8", errors="replace"
                )

                raise TransferError(
                    f"server error {code}: {message}"
                )

            if packet.ptype != expected_type:
                continue

            if (
                expected_seq is not None
                and packet.seq != expected_seq
            ):
                continue

            if expected_type == P.SYN_ACK and packet.payload:
                continue

            if expected_type == P.ACK and packet.payload and not self.selective:
                continue

            if expected_type == P.FIN_ACK:
                if (
                    len(packet.payload) != 1
                    or packet.payload[0] not in STATUS_NAMES
                ):
                    continue

            self.log("RECEIVE", packet.seq)
            return packet

    def exchange(
        self,
        ptype,
        seq,
        payload,
        reply_type,
        reply_seq,
        attempts,
    ):
        """Send a control packet with bounded retries."""
        encoded = P.encode(
            ptype,
            self.transfer_id,
            seq,
            payload,
        )

        rto = BASE_RTO

        for attempt in range(attempts):
            self.send_packet(encoded, seq)

            event = "SEND" if attempt == 0 else "RESEND"
            self.log(f"{event}_{P_NAMES[ptype]}", seq)

            reply = self.wait_for(
                reply_type,
                reply_seq,
                rto,
            )

            if reply is not None:
                return reply

            self.log("TIMEOUT", seq)
            rto = min(rto * 2, MAX_RTO)

        raise TransferError(
            f"retry limit reached for {P_NAMES[ptype]}, "
            f"sequence {seq}"
        )

    def send_chunks(self, file_handle, chunk_size, total_chunks):
        """Send chunks using one timer and a Go-Back-N window."""
        self.base = 0
        self.next_seq = 0

        outstanding = {}
        rto = BASE_RTO
        deadline = None
        consecutive_timeouts = 0

        while self.base < total_chunks:
            # Send new chunks while there is room in the window.
            while (
                self.next_seq < total_chunks
                and self.next_seq < self.base + self.window
            ):
                seq = self.next_seq
                payload = file_handle.read(chunk_size)

                expected_size = min(
                    chunk_size,
                    self.file_size - seq * chunk_size,
                )

                if len(payload) != expected_size:
                    raise TransferError(
                        "file size changed during transfer"
                    )

                encoded = P.encode(
                    P.DATA,
                    self.transfer_id,
                    seq,
                    payload,
                )

                outstanding[seq] = encoded
                self.send_packet(encoded, seq)
                self.next_seq += 1

                # Only the first outstanding packet starts the timer.
                if deadline is None:
                    deadline = time.monotonic() + rto

                self.log("SEND_DATA", seq)
                self.progress()

            remaining = deadline - time.monotonic()

            if remaining > 0:
                reply = self.wait_for(
                    P.ACK,
                    None,
                    remaining,
                )
            else:
                reply = None

            if reply is not None:
                ack = reply.seq

                # Ignore old ACKs and ACKs for data not yet sent.
                if not self.base < ack <= self.next_seq:
                    self.log("IGNORE_ACK", ack)
                    continue

                for seq in range(self.base, ack):
                    del outstanding[seq]

                self.base = ack
                self.acked_bytes = min(
                    self.base * chunk_size,
                    self.file_size,
                )

                consecutive_timeouts = 0
                rto = BASE_RTO

                if self.base < self.next_seq:
                    deadline = time.monotonic() + rto
                else:
                    deadline = None

                self.log("ACK_ADVANCE", ack)
                self.progress()
                continue

            consecutive_timeouts += 1
            self.log("TIMEOUT_DATA", self.base)

            if consecutive_timeouts >= DATA_ATTEMPTS:
                raise TransferError(
                    "ten consecutive DATA timeouts"
                )

            # Resend all outstanding chunks.
            for seq in range(self.base, self.next_seq):
                self.send_packet(outstanding[seq], seq)
                self.retransmissions += 1
                self.log("RESEND_DATA", seq)
                self.progress()

            rto = min(rto * 2, MAX_RTO)
            deadline = time.monotonic() + rto

    def send_file(self, file_handle, file_name, digest, chunk_size):
        name_bytes = file_name.encode("utf-8")

        if len(name_bytes) + SYN_FMT.size > P.MAX_PAYLOAD:
            raise TransferError(
                "file name is too long for SYN"
            )

        total_chunks = (
            self.file_size + chunk_size - 1
        ) // chunk_size

        if total_chunks > 0xFFFFFFFF:
            raise TransferError(
                "file requires too many chunks"
            )

        syn_payload = SYN_FMT.pack(
            self.file_size,
            chunk_size,
            digest,
            len(name_bytes),
        ) + name_bytes + self.syn_options()

        print(
            f"Starting transfer with window {self.window}...",
            flush=True,
        )

        # Completion time starts just before the SYN exchange.
        self.started = time.monotonic()
        self.last_progress = self.started

        self.exchange(
            P.SYN,
            0,
            syn_payload,
            P.SYN_ACK,
            0,
            SYN_ATTEMPTS,
        )

        print(
            "Server accepted the transfer.",
            flush=True,
        )

        self.send_chunks(
            file_handle,
            chunk_size,
            total_chunks,
        )

        reply = self.exchange(
            P.FIN,
            total_chunks,
            b"",
            P.FIN_ACK,
            total_chunks,
            FIN_ATTEMPTS,
        )

        elapsed = max(
            time.monotonic() - self.started,
            0.000001,
        )

        status = STATUS_NAMES[reply.payload[0]]
        goodput = self.file_size * 8 / elapsed

        total_data_sends = (
            total_chunks + self.retransmissions
        )
        retransmission_ratio = (
            self.retransmissions / total_data_sends
            if total_data_sends
            else 0.0
        )

        self.progress(force=True)
        self.log(f"FINISH_{status}", total_chunks)

        print(f"\nVerification: {status}")
        print(f"Completion time: {elapsed:.3f} seconds")
        print(f"Goodput: {goodput / 1_000_000:.3f} Mbps")
        print(
            f"DATA retransmissions: {self.retransmissions}"
        )
        print(
            f"Retransmission ratio: "
            f"{retransmission_ratio:.2%}"
        )

        if status != "OK":
            raise TransferError(
                f"file verification failed: {status}"
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Reliable UDP client: stop-and-wait and Go-Back-N"
        )
    )

    parser.add_argument("file", type=Path)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5005)
    parser.add_argument("--window", type=int, default=1)
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1024,
    )
    parser.add_argument("--log", type=Path, default=None)
    parser.add_argument(
        "--selective",
        action="store_true",
        help="selective retransmission (extension E1)",
    )

    args = parser.parse_args()

    if not 1 <= args.window <= 256:
        parser.error(
            "window must be between 1 and 256"
        )

    if not 1 <= args.chunk_size <= P.MAX_PAYLOAD:
        parser.error(
            "chunk size must be between 1 and 1400"
        )

    if not 1 <= args.port <= 65535:
        parser.error(
            "port must be between 1 and 65535"
        )

    transfer_id = secrets.randbits(32)

    log_path = args.log or Path(
        f"logs/transfer_{transfer_id:08x}.csv"
    )

    try:
        # Prevent the log from overwriting the input file.
        if log_path.resolve() == args.file.resolve():
            raise TransferError(
                "the log path must differ from the input file"
            )

        with args.file.open("rb") as source:
            hasher = hashlib.sha256()
            file_size = 0

            for block in iter(
                lambda: source.read(65536),
                b"",
            ):
                hasher.update(block)
                file_size += len(block)

            source.seek(0)

            log_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with log_path.open(
                "w",
                newline="",
                encoding="utf-8",
            ) as log_file:
                writer = csv.writer(log_file)

                writer.writerow([
                    "elapsed_seconds",
                    "event",
                    "sequence",
                    "acknowledged_bytes",
                    "window",
                    "base",
                    "next_seq",
                    "data_retransmissions",
                ])

                with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_DGRAM,
                ) as sock:
                    # UDP connect selects the peer; it does not use TCP.
                    sock.connect(
                        (args.host, args.port)
                    )

                    if sys.platform == "win32":
                        try:
                            sock.ioctl(
                                socket.SIO_UDP_CONNRESET,
                                False,
                            )
                        except (
                            AttributeError,
                            OSError,
                        ):
                            # send_packet() and wait_for() also handle
                            # connection resets if this option fails.
                            pass

                    if args.selective:
                        from rft.selective import SelectiveClient

                        client_class = SelectiveClient
                    else:
                        client_class = Client

                    client = client_class(
                        sock,
                        transfer_id,
                        file_size,
                        writer,
                        window=args.window,
                    )

                    client.send_file(
                        source,
                        args.file.name,
                        hasher.digest(),
                        args.chunk_size,
                    )

        print(f"Event log: {log_path}")
        return 0

    except (
        OSError,
        TransferError,
        ValueError,
    ) as error:
        print(
            f"Transfer failed: {error}",
            file=sys.stderr,
        )
        return 1

    except KeyboardInterrupt:
        print(
            "\nTransfer cancelled.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())