"""Tests for the reliable UDP sender.

These tests use a simulated receiver and clock.
The actual server and proxy do not need to be running.
"""

import csv
import hashlib
import io
import socket
from collections import Counter, deque

import pytest

from rft import client as C
from rft import packet as P


class FakeClock:
    """Move time forward without waiting in real time."""

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class FakeSocket:
    """Simulate a receiver with cumulative acknowledgements."""

    def __init__(self, clock):
        self.clock = clock
        self.timeout = 0.2

        self.replies = deque()
        self.sent = []
        self.counts = Counter()

        self.expected = 0
        self.received = bytearray()
        self.metadata = None
        self.name = None

        self.silent = False
        self.drop_data_once = set()
        self.drop_reply_once = set()
        self.drop_all_replies = set()

        self.add_bad_acks = False
        self.only_bad_acks = False
        self.corrupt_ack_once = False
        self.error_on_syn = False
        self.fin_status = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def queue_reply(self, ptype, tid, seq, payload=b""):
        if ptype in self.drop_all_replies:
            return

        if ptype in self.drop_reply_once:
            self.drop_reply_once.remove(ptype)
            return

        self.replies.append(
            P.encode(ptype, tid, seq, payload)
        )

    def send(self, raw):
        packet = P.decode(raw)

        self.sent.append(packet)
        self.counts[(packet.ptype, packet.seq)] += 1

        if self.silent:
            return len(raw)

        tid = packet.transfer_id

        if packet.ptype == P.SYN:
            if self.error_on_syn:
                self.queue_reply(
                    P.ERROR,
                    tid,
                    0,
                    b"\x01rejected",
                )
                return len(raw)

            metadata = C.SYN_FMT.unpack_from(packet.payload)
            size, chunk, digest, name_length = metadata
            name = packet.payload[C.SYN_FMT.size:]

            assert len(name) == name_length

            # A duplicate SYN must not reset received data.
            if self.metadata is None:
                self.metadata = (size, chunk, digest)
                self.name = name.decode("utf-8")

            self.queue_reply(P.SYN_ACK, tid, 0)

        elif packet.ptype == P.DATA:
            if packet.seq in self.drop_data_once:
                self.drop_data_once.remove(packet.seq)
                return len(raw)

            if self.only_bad_acks:
                self.queue_reply(P.ACK, tid, 0)
                return len(raw)

            # Go-Back-N receiver: write only the expected chunk.
            if packet.seq == self.expected:
                self.received.extend(packet.payload)
                self.expected += 1

            if self.add_bad_acks:
                # Duplicate or non-advancing ACK.
                self.queue_reply(P.ACK, tid, 0)

                # ACK for data that has not been sent.
                self.queue_reply(
                    P.ACK,
                    tid,
                    0xFFFFFFFF,
                )

                # ACK belonging to another transfer.
                self.queue_reply(
                    P.ACK,
                    tid ^ 1,
                    self.expected,
                )

            if self.corrupt_ack_once:
                damaged = bytearray(
                    P.encode(P.ACK, tid, self.expected)
                )
                damaged[-1] ^= 1
                self.replies.append(bytes(damaged))
                self.corrupt_ack_once = False

            self.queue_reply(
                P.ACK,
                tid,
                self.expected,
            )

        elif packet.ptype == P.FIN:
            size, chunk, digest = self.metadata
            total_chunks = (size + chunk - 1) // chunk

            if (
                len(self.received) != size
                or self.expected != total_chunks
                or packet.seq != total_chunks
            ):
                status = 2

            elif (
                hashlib.sha256(self.received).digest()
                != digest
            ):
                status = 1

            else:
                status = 0

            if self.fin_status is not None:
                status = self.fin_status

            self.queue_reply(
                P.FIN_ACK,
                tid,
                packet.seq,
                bytes([status]),
            )

        return len(raw)

    def recv(self, size):
        if self.replies:
            self.clock.now += 0.0001
            return self.replies.popleft()

        self.clock.now += self.timeout
        raise socket.timeout()


@pytest.fixture
def setup_sender(monkeypatch):
    clock = FakeClock()

    monkeypatch.setattr(
        C.time,
        "monotonic",
        clock.monotonic,
    )

    def make(data, window=1):
        sock = FakeSocket(clock)
        log = io.StringIO()
        writer = csv.writer(log)

        sender = C.Client(
            sock,
            transfer_id=123,
            file_size=len(data),
            writer=writer,
            window=window,
        )

        return sender, sock, log, clock

    return make


def transfer(sender, data, chunk_size=1024):
    sender.send_file(
        io.BytesIO(data),
        "test.bin",
        hashlib.sha256(data).digest(),
        chunk_size,
    )


@pytest.mark.parametrize("window", [1, 4, 32, 256])
def test_transfer_with_different_windows(setup_sender, window):
    data = bytes(range(256)) * 20 + b"end"

    sender, sock, log, clock = setup_sender(
        data,
        window=window,
    )

    transfer(sender, data)

    assert bytes(sock.received) == data
    assert sender.acked_bytes == len(data)
    assert sender.retransmissions == 0

    rows = list(
        csv.reader(io.StringIO(log.getvalue()))
    )

    # The number of outstanding chunks must never exceed W.
    for row in rows:
        base = int(row[5])
        next_seq = int(row[6])

        assert 0 <= next_seq - base <= window

    # The sender should fill the initial window before waiting.
    first_ack = next(
        index
        for index, row in enumerate(rows)
        if row[1] == "ACK_ADVANCE"
    )

    initial_sends = sum(
        row[1] == "SEND_DATA"
        for row in rows[:first_ack]
    )

    total_chunks = (len(data) + 1023) // 1024

    assert initial_sends == min(window, total_chunks)


@pytest.mark.parametrize(
    "data",
    [b"", b"x", b"a" * 1500],
)
def test_empty_small_and_short_final_chunk(setup_sender, data):
    sender, sock, log, clock = setup_sender(data)

    transfer(sender, data)

    assert bytes(sock.received) == data
    assert sender.acked_bytes == len(data)

    chunks = [
        packet
        for packet in sock.sent
        if packet.ptype == P.DATA
    ]

    expected_chunks = (len(data) + 1023) // 1024

    assert len(chunks) == expected_chunks

    if chunks:
        expected_last_size = (
            len(data) - 1024 * (len(chunks) - 1)
        )

        assert len(chunks[-1].payload) == expected_last_size

    else:
        # Empty files still require setup and completion.
        assert sock.counts[(P.SYN, 0)] == 1
        assert sock.counts[(P.FIN, 0)] == 1


def test_lost_data_resends_outstanding_window(setup_sender):
    data = b"a" * (4 * 1024)

    sender, sock, log, clock = setup_sender(
        data,
        window=4,
    )

    sock.drop_data_once.add(0)

    transfer(sender, data)

    assert bytes(sock.received) == data
    assert sender.retransmissions == 4

    for seq in range(4):
        assert sock.counts[(P.DATA, seq)] == 2


def test_lost_ack_causes_retransmission(setup_sender):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.drop_reply_once.add(P.ACK)

    transfer(sender, data)

    assert bytes(sock.received) == data
    assert sender.retransmissions == 1
    assert sock.counts[(P.DATA, 0)] == 2


def test_later_cumulative_ack_covers_lost_ack(setup_sender):
    data = b"a" * (4 * 1024)

    sender, sock, log, clock = setup_sender(
        data,
        window=4,
    )

    sock.drop_reply_once.add(P.ACK)

    transfer(sender, data)

    assert bytes(sock.received) == data
    assert sender.retransmissions == 0


def test_duplicate_and_invalid_acks_are_ignored(setup_sender):
    data = b"a" * 3000

    sender, sock, log, clock = setup_sender(
        data,
        window=4,
    )

    sock.add_bad_acks = True

    transfer(sender, data)

    assert bytes(sock.received) == data
    assert sender.retransmissions == 0
    assert "IGNORE_ACK" in log.getvalue()


def test_corrupted_ack_is_ignored(setup_sender):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.corrupt_ack_once = True

    transfer(sender, data)

    assert bytes(sock.received) == data
    assert "DROP_INVALID" in log.getvalue()


@pytest.mark.parametrize(
    "reply_type",
    [P.SYN_ACK, P.FIN_ACK],
)
def test_setup_and_teardown_retries(setup_sender, reply_type):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.drop_reply_once.add(reply_type)

    transfer(sender, data)

    if reply_type == P.SYN_ACK:
        sent_type = P.SYN
        seq = 0
    else:
        sent_type = P.FIN
        seq = 1

    assert sock.counts[(sent_type, seq)] == 2
    assert bytes(sock.received) == data


def test_syn_retry_limit(setup_sender):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.silent = True

    with pytest.raises(
        C.TransferError,
        match="retry limit",
    ):
        transfer(sender, data)

    assert sock.counts[(P.SYN, 0)] == C.SYN_ATTEMPTS

    assert not any(
        packet.ptype == P.DATA
        for packet in sock.sent
    )


def test_fin_retry_limit(setup_sender):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.drop_all_replies.add(P.FIN_ACK)

    with pytest.raises(
        C.TransferError,
        match="retry limit",
    ):
        transfer(sender, data)

    assert bytes(sock.received) == data
    assert sock.counts[(P.FIN, 1)] == C.FIN_ATTEMPTS


def test_data_timeout_limit_and_backoff(setup_sender):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.only_bad_acks = True

    with pytest.raises(
        C.TransferError,
        match="DATA timeouts",
    ):
        transfer(sender, data)

    assert sock.counts[(P.DATA, 0)] == C.DATA_ATTEMPTS

    assert (
        sender.retransmissions
        == C.DATA_ATTEMPTS - 1
    )

    rows = list(
        csv.reader(io.StringIO(log.getvalue()))
    )

    timeout_times = [
        float(row[0])
        for row in rows
        if row[1] == "TIMEOUT_DATA"
    ]

    assert len(timeout_times) == C.DATA_ATTEMPTS

    intervals = [
        later - earlier
        for earlier, later in zip(
            timeout_times,
            timeout_times[1:],
        )
    ]

    expected = [
        min(
            C.BASE_RTO * 2 ** index,
            C.MAX_RTO,
        )
        for index in range(1, C.DATA_ATTEMPTS)
    ]

    assert intervals == pytest.approx(
        expected,
        abs=0.002,
    )


def test_server_error_stops_transfer(setup_sender):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.error_on_syn = True

    with pytest.raises(
        C.TransferError,
        match="rejected",
    ):
        transfer(sender, data)

    assert not any(
        packet.ptype == P.DATA
        for packet in sock.sent
    )


@pytest.mark.parametrize(
    "status, message",
    [
        (1, "HASH_MISMATCH"),
        (2, "SIZE_MISMATCH"),
    ],
)
def test_failed_verification_is_reported(
    setup_sender,
    status,
    message,
):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    sock.fin_status = status

    with pytest.raises(
        C.TransferError,
        match=message,
    ):
        transfer(sender, data)

    assert f"FINISH_{message}" in log.getvalue()


def test_send_connection_reset_retries(
    setup_sender,
    monkeypatch,
):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    original_send = sock.send
    reset_count = 0

    def send_with_reset(raw):
        nonlocal reset_count

        packet = P.decode(raw)

        if packet.ptype == P.DATA and reset_count == 0:
            reset_count += 1

            raise ConnectionResetError(
                10054,
                "UDP reset",
            )

        return original_send(raw)

    monkeypatch.setattr(
        sock,
        "send",
        send_with_reset,
    )

    transfer(sender, data)

    assert reset_count == 1
    assert bytes(sock.received) == data
    assert sender.retransmissions == 1
    assert "CONNECTION_RESET_SEND" in log.getvalue()


def test_receive_resets_reach_timeout_limit(
    setup_sender,
    monkeypatch,
):
    data = b"hello"
    sender, sock, log, clock = setup_sender(data)

    original_recv = sock.recv

    def recv_with_reset(size):
        data_started = any(
            packet.ptype == P.DATA
            for packet in sock.sent
        )

        if data_started:
            # Advance simulated time so the deadline can expire.
            clock.now += sock.timeout

            raise ConnectionResetError(
                10054,
                "UDP reset",
            )

        return original_recv(size)

    monkeypatch.setattr(
        sock,
        "recv",
        recv_with_reset,
    )

    with pytest.raises(
        C.TransferError,
        match="DATA timeouts",
    ):
        transfer(sender, data)

    assert sock.counts[(P.DATA, 0)] == C.DATA_ATTEMPTS
    assert "CONNECTION_RESET_RECV" in log.getvalue()