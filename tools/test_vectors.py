#!/usr/bin/env python3
"""Offline sanity tests. These are NOT independent Noise interop verification."""
import json
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from generate_vectors import vectors, nonce, header, HEADER_LEN, MTU, CLIENT_CID, SERVER_CID

class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((Path(__file__).resolve().parents[1]/'spec/v1/vectors/native_udp_ik.json').read_text())

    def test_generator_is_deterministic(self):
        self.assertEqual(self.expected, vectors())

    def test_handshake_prefix_size_and_routing(self):
        h = self.expected['handshake']
        init = bytes.fromhex(h['initial']['packet_hex'])
        response = bytes.fromhex(h['response']['packet_hex'])
        self.assertEqual(len(init), 156)
        self.assertEqual(len(response), 108)
        self.assertEqual(init[8:16], bytes(8))
        self.assertEqual(response[8:16], CLIENT_CID)
        self.assertEqual(init[26:58], bytes.fromhex(self.expected['ephemeral_test_keys']['client_public_hex']))
        self.assertEqual(response[26:58], bytes.fromhex(self.expected['ephemeral_test_keys']['server_public_hex']))

    def test_aead_header_authentication(self):
        keys = self.expected['handshake']
        for i, packet in enumerate(self.expected['protected_packets']):
            key = bytes.fromhex(keys['client_to_server_key_hex'] if i in (0,2,4) else keys['server_to_client_key_hex'])
            hd = bytes.fromhex(packet['header_hex'])
            ct = bytes.fromhex(packet['ciphertext_hex'])
            assert len(hd) == HEADER_LEN
            self.assertEqual(int.from_bytes(hd[24:26], 'big'), len(ct))
            self.assertEqual(ChaCha20Poly1305(key).decrypt(nonce(packet['packet_number']), ct, hd).hex(), packet['plaintext_hex'])
            modified = bytearray(hd)
            modified[11] ^= 1
            with self.assertRaises(InvalidTag):
                ChaCha20Poly1305(key).decrypt(nonce(packet['packet_number']), ct, bytes(modified))
            modified_ct = bytearray(ct)
            modified_ct[-1] ^= 1
            with self.assertRaises(InvalidTag):
                ChaCha20Poly1305(key).decrypt(nonce(packet['packet_number']), bytes(modified_ct), hd)
            self.assertLessEqual(len(hd) + len(ct), MTU)

    def test_mtu(self):
        self.assertEqual(1200 - HEADER_LEN - 16, 1158)
        self.assertEqual(len(header('DATA', SERVER_CID, 1, 1158+16)), HEADER_LEN)

if __name__ == '__main__':
    unittest.main()
