#!/usr/bin/env python3
"""Generate a test-only LEStra v2 ACK AEAD fixture."""

from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def main():
    key = bytes(range(32))
    destination_cid = bytes.fromhex("1122334455667788")
    packet_number = 7

    largest_acked = 104

    bitmap = bytes([0x17]) + bytes(127)

    plaintext = (
        largest_acked.to_bytes(8, "big")
        + bitmap
    )

    header = (
        b"LSTR"
        + bytes([2, 7, 0, 0])
        + destination_cid
        + packet_number.to_bytes(8, "big")
        + (len(plaintext) + 16).to_bytes(2, "big")
    )

    nonce = (
        bytes(4)
        + packet_number.to_bytes(8, "little")
    )

    cipher = ChaCha20Poly1305(key)

    ciphertext = cipher.encrypt(
        nonce,
        plaintext,
        header,
    )

    packet = header + ciphertext

    assert len(header) == 26
    assert len(plaintext) == 136
    assert len(ciphertext) == 152
    assert len(packet) == 178

    assert cipher.decrypt(
        nonce,
        ciphertext,
        header,
    ) == plaintext

    root = Path(__file__).resolve().parent.parent

    path = root / "spec/v1/vectors/native_udp_v2_ack.hex"

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        packet.hex() + "\n",
        encoding="ascii",
    )

    print(f"Generated {path}")
    print(f"Packet: {len(packet)} bytes")


if __name__ == "__main__":
    main()
