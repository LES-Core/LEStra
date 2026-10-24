"""Reference model of LEStra handshake retry/DoS invariants.

No Noise, packet parsing, sockets or crypto. This does NOT validate production security.
"""
import hashlib
import unittest
from dataclasses import dataclass, field


@dataclass
class AmplificationBudget:
    received: int = 0
    sent: int = 0
    validated: bool = False

    def note_receive(self, count: int) -> None:
        if count < 0:
            raise ValueError("negative received bytes")
        self.received += count

    def try_send(self, count: int) -> bool:
        if count < 0:
            raise ValueError("negative outgoing bytes")
        if not self.validated and self.sent + count > 3 * self.received:
            return False
        self.sent += count
        return True


@dataclass
class ServerHandshake:
    source: str | None = None
    initial_digest: bytes | None = None
    confirm_digest: bytes | None = None
    state: str = "LISTENING"
    authenticated: bool = False
    application_deliveries: int = 0
    handshake_response: bytes = b"H" * 108
    ready_response: bytes = b"R" * 42
    budget: AmplificationBudget = field(default_factory=AmplificationBudget)

    def on_initial(self, source: str, packet: bytes, valid_noise_acl: bool) -> bytes | None:
        if len(packet) != 156 or not valid_noise_acl:
            return None
        fingerprint = hashlib.sha256(packet).digest()
        if self.state == "LISTENING":
            self.source = source
            self.initial_digest = fingerprint
            self.state = "HANDSHAKE_SENT"
        elif self.state != "HANDSHAKE_SENT":
            return None
        elif source != self.source or fingerprint != self.initial_digest:
            return None
        self.budget.note_receive(len(packet))
        if self.budget.try_send(len(self.handshake_response)):
            return self.handshake_response
        return None

    def on_confirm(self, source: str, packet: bytes, valid_aead: bool) -> bytes | None:
        if source != self.source or len(packet) != 42 or not valid_aead:
            return None
        fingerprint = hashlib.sha256(packet).digest()
        if self.state == "HANDSHAKE_SENT":
            self.confirm_digest = fingerprint
            self.authenticated = True
            self.budget.note_receive(len(packet))
            self.budget.validated = True
            self.state = "ESTABLISHED"
        elif self.state != "ESTABLISHED" or fingerprint != self.confirm_digest:
            return None
        else:
            # Only idempotently resend cached READY for an identical CONFIRM.
            self.budget.note_receive(len(packet))
        return self.ready_response if self.budget.try_send(len(self.ready_response)) else None

    def deliver_data(self, source: str, valid_new_aead: bool) -> bool:
        if self.state != "ESTABLISHED" or source != self.source or not valid_new_aead:
            return False
        self.application_deliveries += 1
        return True


class HandshakeStateTests(unittest.TestCase):
    SOURCE = "192.0.2.10:30000"
    OTHER = "192.0.2.11:30000"
    INITIAL = b"I" * 156
    CONFIRM = b"C" * 42

    def test_old_initial_does_not_trigger_handshake_after_establishment(self):
        server = ServerHandshake()
        server.on_initial(self.SOURCE, self.INITIAL, True)
        self.assertEqual(server.on_confirm(self.SOURCE, self.CONFIRM, True), b"R" * 42)
        before = server.budget.sent
        self.assertIsNone(server.on_initial(self.SOURCE, self.INITIAL, True))
        self.assertEqual(server.budget.sent, before)

    def test_lost_handshake_reuses_identical_response(self):
        server = ServerHandshake()
        first = server.on_initial(self.SOURCE, self.INITIAL, True)
        self.assertEqual(first, b"H" * 108)
        self.assertEqual(server.on_initial(self.SOURCE, self.INITIAL, True), first)
        self.assertEqual(server.state, "HANDSHAKE_SENT")
        self.assertFalse(server.deliver_data(self.SOURCE, True))

    def test_amplification_including_all_resends(self):
        server = ServerHandshake()
        server.on_initial(self.SOURCE, self.INITIAL, True)
        self.assertLessEqual(server.budget.sent, 3 * server.budget.received)
        # Timeouts alone give no byte credit; only real received packets do.
        budget = AmplificationBudget(received=156)
        self.assertTrue(all(budget.try_send(108) for _ in range(4)))
        self.assertFalse(budget.try_send(108))
        self.assertEqual(budget.sent, 432)

    def test_source_mismatch_and_fingerprint_rejected(self):
        server = ServerHandshake()
        server.on_initial(self.SOURCE, self.INITIAL, True)
        self.assertIsNone(server.on_initial(self.OTHER, self.INITIAL, True))
        self.assertIsNone(server.on_initial(self.SOURCE, b"X" * 156, True))
        self.assertEqual(server.source, self.SOURCE)

    def test_acl_failure_no_state_allocated(self):
        server = ServerHandshake()
        self.assertIsNone(server.on_initial(self.SOURCE, self.INITIAL, False))
        self.assertEqual(server.state, "LISTENING")
        self.assertEqual(server.budget.sent, 0)

    def test_lost_ready_resends_identical_bytes_without_delivery(self):
        server = ServerHandshake()
        server.on_initial(self.SOURCE, self.INITIAL, True)
        ready = server.on_confirm(self.SOURCE, self.CONFIRM, True)
        self.assertEqual(ready, b"R" * 42)
        self.assertEqual(server.on_confirm(self.SOURCE, self.CONFIRM, True), ready)
        self.assertEqual(server.application_deliveries, 0)
        self.assertEqual(server.state, "ESTABLISHED")

    def test_invalid_confirm_cannot_advance_state(self):
        server = ServerHandshake()
        server.on_initial(self.SOURCE, self.INITIAL, True)
        self.assertIsNone(server.on_confirm(self.SOURCE, self.CONFIRM, False))
        self.assertIsNone(server.on_confirm(self.OTHER, self.CONFIRM, True))
        self.assertEqual(server.state, "HANDSHAKE_SENT")
        self.assertFalse(server.authenticated)

    def test_altered_retransmitted_confirm_rejected(self):
        server = ServerHandshake()
        server.on_initial(self.SOURCE, self.INITIAL, True)
        server.on_confirm(self.SOURCE, self.CONFIRM, True)
        self.assertIsNone(server.on_confirm(self.SOURCE, b"D" * 42, True))
        self.assertIsNone(server.on_confirm(self.OTHER, self.CONFIRM, True))

    def test_no_application_delivery_before_confirm(self):
        server = ServerHandshake()
        server.on_initial(self.SOURCE, self.INITIAL, True)
        self.assertFalse(server.deliver_data(self.SOURCE, True))
        server.on_confirm(self.SOURCE, self.CONFIRM, True)
        self.assertTrue(server.deliver_data(self.SOURCE, True))
        self.assertFalse(server.deliver_data(self.OTHER, True))
        self.assertFalse(server.deliver_data(self.SOURCE, False))
        self.assertEqual(server.application_deliveries, 1)


if __name__ == "__main__":
    unittest.main()
