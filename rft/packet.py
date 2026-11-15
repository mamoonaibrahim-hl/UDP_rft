"""Packet encoding and decoding for reliable file transfer over UDP"""

import struct
import zlib
from typing import NamedTuple


VERSION = 1
HEADER_FMT = "!BBHIII"
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 16 bytes
MAX_PAYLOAD = 1400

SYN, SYN_ACK, DATA, ACK, FIN, FIN_ACK, ERROR = range(1, 8)


class PacketError(ValueError):
    """Raised when a received packet is malformed or corrupted."""


# supports tests that use the original exception name
BadPacket = PacketError


class Packet(NamedTuple):
    ptype: int
    transfer_id: int
    seq: int
    payload: bytes


def encode(ptype, transfer_id, seq, payload=b""):
    """Build a packet containing a header, payload and CRC32."""

    if not isinstance(ptype, int) or not SYN <= ptype <= ERROR:
        raise ValueError("invalid packet type")

    if not isinstance(transfer_id, int) or not 0 <= transfer_id <= 0xFFFFFFFF:
        raise ValueError("transfer ID must be an unsigned 32-bit integer")

    if not isinstance(seq, int) or not 0 <= seq <= 0xFFFFFFFF:
        raise ValueError("sequence number must be an unsigned 32-bit integer")

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")

    payload = bytes(payload)

    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too large")

    # calculate CRC with the CRC field temporarily set to zero
    header = struct.pack(
        HEADER_FMT,
        VERSION,
        ptype,
        len(payload),
        transfer_id,
        seq,
        0,
    )

    crc = zlib.crc32(header + payload) & 0xFFFFFFFF

    # build the final header using the calculated CRC
    header = struct.pack(
        HEADER_FMT,
        VERSION,
        ptype,
        len(payload),
        transfer_id,
        seq,
        crc,
    )

    return header + payload


def decode(data):
    """Validate a packet and return its type, transfer ID, sequence and payload."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise PacketError("packet must be bytes-like")

    data = bytes(data)

    if len(data) < HEADER_LEN:
        raise PacketError("packet too short")

    version, ptype, plen, transfer_id, seq, received_crc = struct.unpack_from(
        HEADER_FMT, data
    )

    if version != VERSION:
        raise PacketError("unsupported version")

    if not SYN <= ptype <= ERROR:
        raise PacketError("invalid packet type")

    if plen > MAX_PAYLOAD:
        raise PacketError("payload too large")

    payload = data[HEADER_LEN:]

    if plen != len(payload):
        raise PacketError("payload length mismatch")

    # recalculate CRC using a header with its CRC field set to zero
    header = struct.pack(
        HEADER_FMT,
        version,
        ptype,
        plen,
        transfer_id,
        seq,
        0,
    )

    calculated_crc = zlib.crc32(header + payload) & 0xFFFFFFFF

    if calculated_crc != received_crc:
        raise PacketError("CRC mismatch")

    return Packet(ptype, transfer_id, seq, payload)