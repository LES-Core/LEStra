"""Deterministic LEStra handshake network/fault model (M0.3).

Symbolic packets and trusted/invalid flags, NOT Noise, AEAD, sockets or a
production congestion controller. Exercise packet events, not security claims.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import heapq
import itertools
import unittest

from test_handshake_state import HalfOpenPool, ServerHandshake

SOURCE = "192.0.2.10:31000"
OTHER_SOURCE = "192.0.2.11:31000"
INITIAL = b"I" * 156
HANDSHAKE = b"H" * 108
CONFIRM = b"C" * 42
READY = b"R" * 42
PACKETS = {"INITIAL": INITIAL, "HANDSHAKE": HANDSHAKE,
           "CONFIRM": CONFIRM, "READY": READY}


@dataclass
class RetrySettings:
    # Simulation defaults, not normative wire/RTO values.
    initial_rto_ms: int = 100
    max_rto_ms: int = 800
    total_deadline_ms: int = 2200
    max_transmissions_per_flight: int = 5
    one_way_delay_ms: int = 5


@dataclass
class NetworkPolicy:
    drop_first: dict[str, int] = field(default_factory=dict)
    duplicate: frozenset[str] = frozenset()
    extra_delay_ms: dict[str, int] = field(default_factory=dict)


class HandshakeNetwork:
    def __init__(self, policy: NetworkPolicy | None = None,
                 settings: RetrySettings | None = None):
        self.policy = policy or NetworkPolicy()
        self.settings = settings or RetrySettings()
        self.server = ServerHandshake()
        self.client_phase = "INITIAL_SENT"
        self.now_ms = 0
        self.order = itertools.count()
        self.queue: list[tuple[int, int, str, str]] = []
        self.sent = Counter()
        self.delivered = Counter()
        self.discarded = Counter()
        self.history: list[tuple[int, str, str]] = []
        self.client_payloads = 0
        self.timers: dict[str, int] = {"INITIAL": 0, "CONFIRM": 0}
        self.tx_by_flight = Counter()

    def _enqueue(self, deadline_ms: int, kind: str, event: str) -> None:
        heapq.heappush(self.queue, (deadline_ms, next(self.order), kind, event))

    def send(self, kind: str) -> None:
        self.sent[kind] += 1
        self.history.append((self.now_ms, "send", kind))
        if self.sent[kind] <= self.policy.drop_first.get(kind, 0):
            self.discarded[kind] += 1
            return
        delay = self.settings.one_way_delay_ms + self.policy.extra_delay_ms.get(kind, 0)
        self._enqueue(self.now_ms + delay, kind, "deliver")
        if kind in self.policy.duplicate:
            self._enqueue(self.now_ms + delay + 3, kind, "deliver")

    def _client_send(self, kind: str) -> None:
        assert kind in ("INITIAL", "CONFIRM")
        self.tx_by_flight[kind] += 1
        self.send(kind)
        # A real implementation adds jitter. This finite model is deterministic.
        rto = min(self.settings.initial_rto_ms * (2 ** (self.tx_by_flight[kind] - 1)),
                  self.settings.max_rto_ms)
        self.timers[kind] += 1
        self._enqueue(self.now_ms + rto, kind, f"timeout:{self.timers[kind]}")

    def start(self) -> None:
        self._client_send("INITIAL")

    def _handle_delivery(self, kind: str) -> None:
        self.delivered[kind] += 1
        if kind == "INITIAL":
            packet = self.server.on_initial(SOURCE, INITIAL, True)
            if packet is not None:
                assert packet == HANDSHAKE
                self.send("HANDSHAKE")
        elif kind == "HANDSHAKE":
            if self.client_phase == "INITIAL_SENT":
                self.client_phase = "CONFIRM_SENT"
                self._client_send("CONFIRM")
            elif self.client_phase == "CONFIRM_SENT":
                # May retransmit byte-identical CONFIRM, within budget.
                if self.tx_by_flight["CONFIRM"] < self.settings.max_transmissions_per_flight:
                    self._client_send("CONFIRM")
        elif kind == "CONFIRM":
            reply = self.server.on_confirm(SOURCE, CONFIRM, True)
            if reply is not None:
                assert reply == READY
                self.send("READY")
        elif kind == "READY":
            if self.client_phase == "CONFIRM_SENT":
                self.client_phase = "ESTABLISHED"
        else:
            raise AssertionError(kind)

    def _timeout(self, kind: str, generation: int) -> None:
        if self.client_phase == "ESTABLISHED":
            return
        wanted_phase = {"INITIAL": "INITIAL_SENT", "CONFIRM": "CONFIRM_SENT"}[kind]
        if generation != self.timers[kind] or self.client_phase != wanted_phase:
            return
        if (self.now_ms >= self.settings.total_deadline_ms
                or self.tx_by_flight[kind] >= self.settings.max_transmissions_per_flight):
            self.client_phase = "FAILED"
            return
        self._client_send(kind)

    def run(self) -> "HandshakeNetwork":
        self.start()
        while self.queue:
            now, _, kind, event = heapq.heappop(self.queue)
            self.now_ms = now
            if now > self.settings.total_deadline_ms:
                if self.client_phase != "ESTABLISHED":
                    self.client_phase = "FAILED"
                break
            if event == "deliver":
                self._handle_delivery(kind)
            else:
                self._timeout(kind, int(event.split(":", 1)[1]))
            if self.client_phase == "FAILED":
                break
            assert sum(self.sent.values()) <= 128, "unbounded retransmission model"
        if self.client_phase != "ESTABLISHED":
            self.client_phase = "FAILED"
        return self


class NetworkFaultTests(unittest.TestCase):
    def assert_established(self, fault: NetworkPolicy) -> HandshakeNetwork:
        sim = HandshakeNetwork(fault).run()
        self.assertEqual(sim.client_phase, "ESTABLISHED")
        self.assertEqual(sim.server.state, "ESTABLISHED")
        self.assertEqual(sim.server.application_deliveries, 0)
        self.assertEqual(sim.client_payloads, 0)
        self.assertEqual(sim.server.handshake_response, HANDSHAKE)
        self.assertEqual(sim.server.ready_response, READY)
        self.assertLessEqual(sum(sim.sent.values()), 128)
        return sim

    def test_no_loss(self):
        sim = self.assert_established(NetworkPolicy())
        self.assertEqual([sim.sent[k] for k in PACKETS], [1, 1, 1, 1])

    def test_each_single_flight_loss_recovers(self):
        for kind in PACKETS:
            with self.subTest(kind=kind):
                sim = self.assert_established(NetworkPolicy(drop_first={kind: 1}))
                self.assertGreaterEqual(sim.sent[kind], 2)

    def test_mixed_loss_recovers(self):
        sim = self.assert_established(NetworkPolicy(drop_first={
            "INITIAL": 1, "HANDSHAKE": 1, "CONFIRM": 1, "READY": 1
        }))
        self.assertGreater(sim.sent["INITIAL"], 1)
        self.assertGreater(sim.sent["CONFIRM"], 1)

    def test_duplicate_and_reordered_flights(self):
        sim = self.assert_established(NetworkPolicy(
            duplicate=frozenset(PACKETS), extra_delay_ms={"READY": 15}))
        self.assertGreater(sim.delivered["HANDSHAKE"], 1)
        self.assertEqual(sim.server.application_deliveries, 0)

    def test_permanent_initial_loss_fails_without_infinite_retries(self):
        sim = HandshakeNetwork(NetworkPolicy(drop_first={"INITIAL": 100})).run()
        self.assertEqual(sim.client_phase, "FAILED")
        self.assertEqual(sim.server.state, "LISTENING")
        self.assertLessEqual(sim.sent["INITIAL"], sim.settings.max_transmissions_per_flight)

    def test_permanent_ready_loss_is_bounded_and_cannot_enable_client(self):
        sim = HandshakeNetwork(NetworkPolicy(drop_first={"READY": 100})).run()
        self.assertEqual(sim.client_phase, "FAILED")
        self.assertEqual(sim.server.state, "ESTABLISHED")
        self.assertLessEqual(sim.sent["CONFIRM"], sim.settings.max_transmissions_per_flight)
        self.assertEqual(sim.client_payloads, 0)

    def test_timeout_ceiling_bounds_retry_schedule(self):
        sim = HandshakeNetwork(NetworkPolicy(drop_first={"HANDSHAKE": 100}),
                               RetrySettings(max_transmissions_per_flight=3)).run()
        self.assertEqual(sim.client_phase, "FAILED")
        self.assertLessEqual(sim.tx_by_flight["INITIAL"], 3)

    def test_delayed_ready_beyond_deadline_never_establishes_client(self):
        sim = HandshakeNetwork(NetworkPolicy(extra_delay_ms={"READY": 5000})).run()
        self.assertEqual(sim.client_phase, "FAILED")
        self.assertEqual(sim.server.application_deliveries, 0)

    def test_unbounded_duplicates_cannot_force_unbounded_resends(self):
        server = ServerHandshake()
        handshakes = [server.on_initial(SOURCE, INITIAL, True) for _ in range(30)]
        self.assertEqual(sum(p is not None for p in handshakes), server.max_handshake_sends)
        self.assertLessEqual(server.budget.sent, 3 * server.budget.received)
        ready = [server.on_confirm(SOURCE, CONFIRM, True) for _ in range(30)]
        self.assertEqual(sum(p is not None for p in ready), server.max_ready_sends)
        self.assertEqual(server.application_deliveries, 0)

    def test_source_spoofing_does_not_generate_another_handshake(self):
        server = ServerHandshake()
        self.assertEqual(server.on_initial(SOURCE, INITIAL, True), HANDSHAKE)
        sent = server.budget.sent
        self.assertIsNone(server.on_initial(OTHER_SOURCE, INITIAL, True))
        self.assertEqual(server.budget.sent, sent)

    def test_burst_is_bounded_by_half_open_and_byte_caps(self):
        pool = HalfOpenPool(max_global=64, max_per_source=2,
                            max_cache_bytes=64 * 160, ttl_ms=250)
        admitted = [pool.admit(f"attempt-{i}", f"192.0.2.{(i % 200) + 1}", 160, 0)
                    for i in range(2000)]
        self.assertEqual(sum(admitted), 64)
        self.assertEqual(len(pool.entries), 64)
        self.assertLessEqual(sum(item[1] for item in pool.entries.values()),
                             pool.max_cache_bytes)
        pool.expire(249)
        self.assertEqual(len(pool.entries), 64)
        pool.expire(250)
        self.assertFalse(pool.entries)
        self.assertTrue(pool.admit("next-attempt", "192.0.2.1", 160, 251))


if __name__ == "__main__":
    unittest.main()
