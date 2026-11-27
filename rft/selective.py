"""Selective-retransmission sender (extension E1, Member B).

Differences from the compulsory Go-Back-N client:
  * the SYN carries an option byte so the server buffers early chunks;
  * ACKs carry a bitmap of the chunks the server already holds;
  * after a timeout only the chunks that are NOT held are sent again.
Everything else (window, one timer on the oldest chunk, backoff, retry limit,
progress output, CSV log) is inherited unchanged from rft.client.Client.

Use:  python -m rft.client file.bin --host 127.0.0.1 --port 5005 --window 32 --selective
"""
import time

from rft import packet as P
from rft.client import BASE_RTO, DATA_ATTEMPTS, MAX_RTO, Client, TransferError
from rft.sack import SACK_RANGE, parse_sack


class SelectiveClient(Client):
    selective = True            # tells Client.wait_for to accept ACKs that carry a bitmap

    def syn_options(self):
        return bytes([1])       # bit 0: selective ACKs

    def send_chunks(self, file_handle, chunk_size, total_chunks):
        if self.window > SACK_RANGE:
            raise TransferError("selective mode needs a window of at most 256")
        self.base = 0
        self.next_seq = 0
        outstanding = {}        # chunk number -> encoded packet, until cumulatively acknowledged
        held = set()            # chunks the server says it already has
        rto = BASE_RTO
        deadline = None
        consecutive_timeouts = 0

        while self.base < total_chunks:
            # 1. send new chunks while the window has room
            while self.next_seq < total_chunks and self.next_seq < self.base + self.window:
                seq = self.next_seq
                payload = file_handle.read(chunk_size)
                expected_size = min(chunk_size, self.file_size - seq * chunk_size)
                if len(payload) != expected_size:
                    raise TransferError("file size changed during transfer")
                packet = P.encode(P.DATA, self.transfer_id, seq, payload)
                outstanding[seq] = packet
                self.sock.send(packet)
                self.next_seq += 1
                if deadline is None:
                    deadline = time.monotonic() + rto
                self.log("SEND_DATA", seq)
                self.progress()

            # 2. wait for an ACK until the timer expires
            remaining = deadline - time.monotonic()
            reply = None
            if remaining > 0:
                reply = self.wait_for(P.ACK, None, remaining)

            if reply is not None:
                ack = reply.seq
                if ack < self.base or ack > self.next_seq:
                    self.log("IGNORE_ACK", ack)
                    continue
                for seq in parse_sack(ack, reply.payload):
                    if seq in outstanding:
                        held.add(seq)
                if ack > self.base:                   # the window slides
                    for seq in range(self.base, ack):
                        outstanding.pop(seq, None)
                        held.discard(seq)
                    self.base = ack
                    self.acked_bytes = min(self.base * chunk_size, self.file_size)
                    consecutive_timeouts = 0
                    rto = BASE_RTO
                    if self.base < self.next_seq:
                        deadline = time.monotonic() + rto
                    else:
                        deadline = None
                    self.log("ACK_ADVANCE", ack)
                else:
                    self.log("SACK_INFO", ack)
                self.progress()
                continue

            # 3. timeout: send again only what the server does not hold
            consecutive_timeouts += 1
            self.log("TIMEOUT_DATA", self.base)
            if consecutive_timeouts >= DATA_ATTEMPTS:
                raise TransferError("ten consecutive DATA timeouts")
            for seq in range(self.base, self.next_seq):
                if seq not in held:
                    self.sock.send(outstanding[seq])
                    self.retransmissions += 1
                    self.log("RESEND_DATA", seq)
                    self.progress()
            rto = min(rto * 2, MAX_RTO)
            deadline = time.monotonic() + rto
