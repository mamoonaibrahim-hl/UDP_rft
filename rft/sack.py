"""Selective-ACK bitmap helpers (extension E1). No imports on purpose, so the
server and the client can both use it.

A selective ACK has the usual cumulative number in the header (the next chunk the
receiver expects) and an optional payload: a bitmap. Bit k of the bitmap (byte
k // 8, bit k % 8, counting from the lowest bit) is 1 when chunk
(expected + 1 + k) has already been received and is buffered.
Trailing zero bytes are left out, so "no gaps" gives an empty payload.
"""

SACK_RANGE = 256          # how far ahead of "expected" the bitmap can describe
SACK_BYTES = SACK_RANGE // 8


def make_sack(expected, received):
    """received: any collection of chunk numbers the receiver holds (all > expected)."""
    bits = bytearray(SACK_BYTES)
    last_byte = -1
    for seq in received:
        k = seq - expected - 1
        if 0 <= k < SACK_RANGE:
            bits[k // 8] |= 1 << (k % 8)
            if k // 8 > last_byte:
                last_byte = k // 8
    return bytes(bits[:last_byte + 1])


def parse_sack(expected, payload):
    """Return the set of chunk numbers the bitmap says the receiver holds."""
    held = set()
    for index in range(min(len(payload), SACK_BYTES)):
        byte = payload[index]
        for bit in range(8):
            if byte & (1 << bit):
                held.add(expected + 1 + index * 8 + bit)
    return held
