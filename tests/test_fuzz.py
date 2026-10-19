"""Malformed input must produce CTAP errors, never crashes or hangs."""

import os
import random

from ubuntu_passkey import cbor, ctaphid

COMMANDS = [0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x40, 0xFF]


def _random_value(rng, depth=0):
    kind = rng.randrange(8 if depth < 3 else 5)
    if kind == 0:
        return rng.randrange(-(2**40), 2**40)
    if kind == 1:
        return os.urandom(rng.randrange(0, 80))
    if kind == 2:
        return rng.choice(["", "id", "public-key", "example.com", "x" * 300, "hmac-secret"])
    if kind == 3:
        return rng.choice([True, False, None])
    if kind == 4:
        return rng.random()
    if kind == 5:
        return [_random_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    keys = [rng.randrange(-3, 12), "id", "type", "alg", "rk", "uv", "up", "name"]
    return {rng.choice(keys): _random_value(rng, depth + 1) for _ in range(rng.randrange(6))}


def test_authenticator_survives_random_requests(authenticator):
    rng = random.Random(1234)
    for _ in range(3000):
        cmd = rng.choice(COMMANDS)
        if rng.random() < 0.15:
            payload = os.urandom(rng.randrange(0, 64))
        else:
            params = {rng.randrange(1, 11): _random_value(rng) for _ in range(rng.randrange(8))}
            payload = cbor.encode(params)
        response = authenticator.process(bytes([cmd]) + payload)
        assert isinstance(response, bytes) and len(response) >= 1
        # Status 0x7F (ERR_OTHER) would mean an unexpected exception.
        assert response[0] != 0x7F, (hex(cmd), payload.hex())


def test_ctaphid_survives_random_reports(authenticator):
    sent = []
    dev = ctaphid.CtapHidDevice(authenticator, sent.append)
    rng = random.Random(99)
    for _ in range(3000):
        report = bytearray(os.urandom(rng.choice([1, 7, 63, 64, 65])))
        if rng.random() < 0.5 and len(report) >= 5:
            report[:4] = b"\xff\xff\xff\xff"
        dev.handle_report(bytes(report))
    assert all(len(p) == ctaphid.PACKET_SIZE for p in sent)
