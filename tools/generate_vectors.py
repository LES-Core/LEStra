#!/usr/bin/env python3
"""Deterministic LEStra M0.3 design fixtures — NOT a production Noise implementation.

Test-only X25519 private keys are fully deterministic and publicly disclosed.
An independent Noise implementation MUST verify this suite before wire freeze.
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTO = b"Noise_IK_25519_ChaChaPoly_SHA256"
PROLOGUE = b"LEStra/native-udp/v1"
MAGIC = b"LSTR"
HEADER_LEN = 26
MTU = 1200
TYPES = {"INITIAL": 1, "HANDSHAKE": 2, "CONFIRM": 3, "DATA": 4, "CLOSE": 5, "READY": 6}
CLIENT_CID = bytes.fromhex("1122334455667788")
SERVER_CID = bytes.fromhex("a1a2a3a4a5a6a7a8")


def digest(v: bytes) -> bytes:
    return hashlib.sha256(v).digest()


def hkdf2(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    t = hmac.digest(ck, ikm, 'sha256')
    a = hmac.digest(t, b'\x01', 'sha256')
    b = hmac.digest(t, a + b'\x02', 'sha256')
    return a, b


def pubkey(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def test_private(label: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(digest(('LEStra-M0.3 TEST-ONLY ' + label).encode()))


def dh(a: X25519PrivateKey, b: bytes) -> bytes:
    return a.exchange(X25519PublicKey.from_public_bytes(b))


def nonce(number: int) -> bytes:
    if not 0 <= number < (1 << 64) - 1:
        raise ValueError('Noise nonce exhausted')
    return b'\0' * 4 + number.to_bytes(8, 'little')


def header(kind: str, destination: bytes, pn: int, body_len: int) -> bytes:
    if len(destination) != 8 or not 0 <= pn < (1 << 64) or not 0 <= body_len <= 0xFFFF:
        raise ValueError('invalid header')
    return MAGIC + bytes((1, TYPES[kind])) + b'\0\0' + destination + pn.to_bytes(8, 'big') + body_len.to_bytes(2, 'big')


class Symmetric:
    def __init__(self, server_static: bytes):
        self.h = PROTO.ljust(32, b'\0') if len(PROTO) <= 32 else digest(PROTO)
        self.ck = self.h
        self.k = None
        self.n = 0
        self.mix_hash(PROLOGUE)
        self.mix_hash(server_static)  # IK pre-message: <- s

    def mix_hash(self, data: bytes):
        self.h = digest(self.h + data)

    def mix_key(self, ikm: bytes):
        self.ck, self.k = hkdf2(self.ck, ikm)
        self.n = 0

    def encrypt_and_hash(self, plain: bytes) -> bytes:
        out = plain if self.k is None else ChaCha20Poly1305(self.k).encrypt(nonce(self.n), plain, self.h)
        if self.k is not None:
            self.n += 1
        self.mix_hash(out)
        return out

    def decrypt_and_hash(self, cipher: bytes) -> bytes:
        plain = cipher if self.k is None else ChaCha20Poly1305(self.k).decrypt(nonce(self.n), cipher, self.h)
        if self.k is not None:
            self.n += 1
        self.mix_hash(cipher)
        return plain

    def split(self) -> tuple[bytes, bytes]:
        return hkdf2(self.ck, b'')


def transport(name: str, key: bytes, destination: bytes, pn: int, plain: bytes) -> dict:
    h = header(name, destination, pn, len(plain) + 16)
    cipher = ChaCha20Poly1305(key).encrypt(nonce(pn), plain, h)
    packet = h + cipher
    assert len(packet) <= MTU
    return {'type': name, 'packet_number': pn, 'header_hex': h.hex(), 'plaintext_hex': plain.hex(), 'ciphertext_hex': cipher.hex(), 'packet_hex': packet.hex()}


def vectors() -> dict:
    ci_s, ci_e, sr_s, sr_e = [test_private(x) for x in ('client-static', 'client-ephemeral', 'server-static', 'server-ephemeral')]
    c_pub, ce_pub, s_pub, se_pub = map(pubkey, (ci_s, ci_e, sr_s, sr_e))
    client = Symmetric(s_pub)
    server = Symmetric(s_pub)

    # INITIAL Noise IK: -> e, es, s, ss, payload
    payload1_len = HEADER_LEN + 8
    body1_len = 32 + (32 + 16) + (payload1_len + 16)
    h1 = header('INITIAL', bytes(8), 0, body1_len)
    client.mix_hash(ce_pub)
    client.mix_key(dh(ci_e, s_pub))  # es
    noise1 = ce_pub + client.encrypt_and_hash(c_pub)
    client.mix_key(dh(ci_s, s_pub))  # ss
    noise1 += client.encrypt_and_hash(h1 + CLIENT_CID)
    assert len(noise1) == body1_len
    packet1 = h1 + noise1

    # Responder reads complete first Noise message.
    server.mix_hash(ce_pub)
    server.mix_key(dh(sr_s, ce_pub))  # es
    assert server.decrypt_and_hash(noise1[32:80]) == c_pub
    server.mix_key(dh(sr_s, c_pub))  # ss
    assert server.decrypt_and_hash(noise1[80:]) == h1 + CLIENT_CID
    assert client.h == server.h

    # HANDSHAKE Noise IK: <- e, ee, se, payload
    payload2_len = HEADER_LEN + 8
    body2_len = 32 + payload2_len + 16
    h2 = header('HANDSHAKE', CLIENT_CID, 0, body2_len)
    server.mix_hash(se_pub)
    server.mix_key(dh(sr_e, ce_pub))  # ee
    server.mix_key(dh(sr_e, c_pub))   # se
    noise2 = se_pub + server.encrypt_and_hash(h2 + SERVER_CID)
    packet2 = h2 + noise2
    client.mix_hash(se_pub)
    client.mix_key(dh(ci_e, se_pub)) # ee
    client.mix_key(dh(ci_s, se_pub)) # se
    assert client.decrypt_and_hash(noise2[32:]) == h2 + SERVER_CID
    assert client.h == server.h and client.ck == server.ck
    key_c2s, key_s2c = client.split()
    assert server.split() == (key_c2s, key_s2c)

    # Distinct per-direction traffic keys; header passed as AEAD AD.
    protected = [
        transport('CONFIRM', key_c2s, SERVER_CID, 0, b''),
        transport('READY', key_s2c, CLIENT_CID, 0, b''),
        transport('DATA', key_c2s, SERVER_CID, 1, b'LEStra vector test payload'),
        transport('DATA', key_s2c, CLIENT_CID, 1, b'LEStra reply'),
        transport('CLOSE', key_c2s, SERVER_CID, 2, b''),
    ]
    for obj, k in zip(protected, (key_c2s, key_s2c, key_c2s, key_s2c, key_c2s)):
        out = ChaCha20Poly1305(k).decrypt(nonce(obj['packet_number']), bytes.fromhex(obj['ciphertext_hex']), bytes.fromhex(obj['header_hex']))
        assert out.hex() == obj['plaintext_hex']

    return {
      'warning': 'TEST ONLY: deterministic public private keys, NOT suitable for production',
      'status': 'M0.3 proposed encoding; independent verification REQUIRED',
      'noise_name': PROTO.decode(), 'prologue_hex': PROLOGUE.hex(), 'udp_payload_limit': MTU,
      'static_test_keys': {'client_private_hex':private_bytes(ci_s).hex(),'client_public_hex':c_pub.hex(), 'server_private_hex':private_bytes(sr_s).hex(),'server_public_hex':s_pub.hex()},
      'ephemeral_test_keys': {'client_private_hex':private_bytes(ci_e).hex(),'client_public_hex':ce_pub.hex(), 'server_private_hex':private_bytes(sr_e).hex(),'server_public_hex':se_pub.hex()},
      'cids': {'client_hex':CLIENT_CID.hex(),'server_hex':SERVER_CID.hex()},
      'handshake': {'initial': {'header_hex': h1.hex(), 'noise_message_hex':noise1.hex(), 'packet_hex':packet1.hex(), 'encrypted_payload_hex':noise1[80:].hex()},
                    'response':{'header_hex':h2.hex(),'noise_message_hex':noise2.hex(),'packet_hex':packet2.hex(),'encrypted_payload_hex':noise2[32:].hex()},
                    'handshake_hash_hex':client.h.hex(),'client_to_server_key_hex':key_c2s.hex(),'server_to_client_key_hex':key_s2c.hex()},
      'protected_packets': protected
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true', help='Compare generated data with committed fixture')
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[1] / 'spec/v1/vectors/native_udp_ik.json'
    output = json.dumps(vectors(), indent=2, ensure_ascii=False) + '\n'
    if args.check:
        if path.read_text(encoding='utf-8') != output:
            raise SystemExit('Fixture mismatch — regenerate and review')
        print('Fixture matches deterministic reference generator')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding='utf-8')
        print(f'Wrote {path}')

if __name__ == '__main__':
    main()
