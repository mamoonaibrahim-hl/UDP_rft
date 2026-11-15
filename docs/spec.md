# Reliable File Transfer over UDP: Protocol Specification

Group 12
Member A: Afeera Usman
Member B: Mamoona Ibrahim

## 1. Purpose

The client uploads one binary file to the server using UDP.
Our protocol adds acknowledgements, retransmissions, duplicate
handling and integrity verification.

The compulsory sliding-window mode uses Go-Back-N.
Stop-and-wait uses the same protocol with window size 1.

## 2. Windows Test Environment

The client, proxy and server run in separate Windows terminals.

- Client sends to 127.0.0.1:5006.
- The impairment proxy listens on port 5006.
- The proxy forwards packets to the server on 127.0.0.1:5005.
- Server replies return through the proxy.

The proxy simulates delay, loss, duplication, corruption,
reordering, rate limits and outages in both directions.

Without the proxy, the client can send directly to port 5005.

## 3. Packet Header

Every packet starts with a 16-byte header.
Fields use network byte order (big-endian).

Python struct format: !BBHIII

| Field | Size | Meaning |
|---|---|---|
| Version | 1 byte | Protocol version, currently 1 |
| Type | 1 byte | Packet type, from 1 to 7 |
| Payload length | 2 bytes | Number of bytes after the header |
| Transfer ID | 4 bytes | Random unsigned ID chosen by the client |
| Sequence number | 4 bytes | Meaning depends on packet type |
| CRC32 | 4 bytes | Integrity check over header and payload |

Maximum payload length: 1400 bytes.
Default DATA chunk size: 1024 bytes.

CRC32 is calculated over the complete header with its CRC field
set to zero, followed by the payload.

The receiver repeats this calculation and rejects the packet
if the CRC values differ.

## 4. Packet Types

| Value | Name | Purpose |
|---|---|---|
| 1 | SYN | Request a new transfer |
| 2 | SYN_ACK | Accept the transfer |
| 3 | DATA | Carry one file chunk |
| 4 | ACK | Acknowledge received chunks |
| 5 | FIN | Request transfer completion |
| 6 | FIN_ACK | Return the final verification result |
| 7 | ERROR | Report a protocol or server error |

## 5. Sequence Numbers

DATA sequence numbers start at 0.

An ACK contains the next expected chunk index.
For example, ACK 4 confirms that chunks 0, 1, 2 and 3
have been received.

FIN and FIN_ACK contain the total number of chunks.

SYN, SYN_ACK and ERROR use sequence number 0.

## 6. Packet Payloads

### SYN

The fixed part uses struct format !QH32sH.

| Field | Size |
|---|---|
| File size in bytes | 8 bytes |
| DATA chunk size | 2 bytes |
| SHA-256 digest | 32 bytes |
| UTF-8 file-name length in bytes | 2 bytes |

The UTF-8 file-name bytes follow the fixed part.
The file-name length counts encoded bytes, not characters.
The complete SYN payload must fit within 1400 bytes.

### DATA

Contains the original file bytes for one chunk.
The last chunk may be shorter than the configured chunk size.
No padding is added.

### FIN_ACK

Contains one status byte:

- 0: OK
- 1: HASH_MISMATCH
- 2: SIZE_MISMATCH

### ERROR

Contains an error-code byte followed by a short UTF-8 message.

### Other packets

SYN_ACK, ACK and FIN have empty payloads.

## 7. Packet Module Interface

The shared module is rft/packet.py.

Constants:
SYN, SYN_ACK, DATA, ACK, FIN, FIN_ACK, ERROR

Functions:

encode(ptype, transfer_id, seq, payload=b"") -> bytes

decode(data) -> Packet(ptype, transfer_id, seq, payload)

Packet supports tuple unpacking and named-field access.

Malformed packets raise PacketError.
BadPacket is an alias for PacketError for compatibility.

The decoder rejects:
- Packets shorter than 16 bytes
- Unsupported versions
- Unknown packet types
- Payloads larger than 1400 bytes
- Payload-length mismatches
- CRC32 mismatches

Packet-type-specific payload validation is handled by the
client or server after decoding.

## 8. Session Setup

The client reads the file, calculates SHA-256 and chooses a
random 32-bit transfer ID.

It sends SYN and waits for a matching SYN_ACK.
If no reply arrives before timeout, SYN is retransmitted.

The client sends SYN once and retries up to five times.
This gives six attempts in total.

A duplicate SYN for an existing session receives the same
SYN_ACK without resetting the received file.

Sessions are identified by:
(client IP address, client UDP port, transfer ID).

## 9. Sender Rules

The sender maintains:

- base: oldest unacknowledged chunk
- next_seq: next chunk to send
- W: configured window size, from 1 to 256

Send new chunks while:
next_seq < base + W

Do not send beyond the total chunk count.

Accept an ACK only from the expected peer, for the current
transfer, and when:
base < ACK sequence number <= next_seq

An advancing ACK moves base forward and resets the timeout
backoff and consecutive-timeout count.

Duplicate or older ACKs do not advance the window and do not
trigger retransmission.

Window size 1 provides stop-and-wait.

## 10. Timer and Retransmission

Use a monotonic clock.

- Initial retransmission timeout: 300 ms
- Maximum retransmission timeout: 3 seconds
- Maximum consecutive DATA timeouts: 10

One timer tracks the oldest unacknowledged chunk.

On timeout:
1. Retransmit every outstanding chunk from base to next_seq - 1.
2. Count each resent DATA chunk as one retransmission.
3. Double the timeout, capped at 3 seconds.
4. Restart the timer.

Abort when the consecutive-timeout limit is reached.
Stop the DATA timer when no chunks remain outstanding.

## 11. Receiver Rules

The receiver maintains the next expected chunk index.

- If seq equals expected, write the chunk once and increment expected.
- If seq is below expected, count it as a duplicate and do not write it.
- If seq is above expected, discard it as out of order.
- After a valid DATA packet, reply with ACK(expected).
- Drop corrupt packets silently and count them.

The compulsory receiver does not buffer out-of-order chunks.

## 12. Transfer Completion

After all DATA chunks are acknowledged, the client sends FIN.

The server checks:
- Received chunk count
- Received file size
- SHA-256 of the received file

It returns FIN_ACK with the verification status.

The client sends FIN up to ten times in total.
The timeout starts at 300 ms and doubles after each timeout,
up to a maximum of 3 seconds.

The server retains completed-session state for 6 seconds
so duplicate FIN packets receive the same FIN_ACK.

Inactive sessions are removed after 30 seconds.

An empty file has zero DATA chunks and proceeds from
session setup directly to FIN.

## 13. Progress and Statistics

The client displays progress at least once per second:

- Percentage of file bytes acknowledged
- Current goodput
- DATA retransmission count

The final summary includes:
- Completion time
- Goodput
- DATA retransmissions
- Final verification status

Completion time runs from the first SYN send to receipt
of the final FIN_ACK.

Goodput in bits per second:
(file size in bytes * 8) / completion time

Retransmission ratio:
DATA retransmissions / total DATA transmissions

A per-run CSV event log records time, event, sequence number
and window state.

## 14. Scope

Compulsory:
- Stop-and-wait
- Go-Back-N sliding window
- CRC32 and SHA-256 verification
- Duplicate handling
- Reliable setup and teardown
- Concurrent sessions
- Bounded retries and error handling

Optional:
- Selective retransmission
- Adaptive timeout estimation

TCP and reliable-transfer libraries are not used for
the file transfer.