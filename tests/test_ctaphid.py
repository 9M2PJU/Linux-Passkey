import os
import struct
import threading
import time

from linux_passkey import ctaphid


class Collector:
    def __init__(self):
        self.packets = []
        self.cond = threading.Condition()

    def __call__(self, packet):
        with self.cond:
            self.packets.append(packet)
            self.cond.notify_all()

    def message(self, timeout=2, skip_keepalive=True):
        """Reassemble the next message from collected packets."""
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                while not self.packets:
                    remaining = deadline - time.monotonic()
                    assert remaining > 0, "timed out"
                    self.cond.wait(remaining)
                first = self.packets.pop(0)
                cid, cmd, length = struct.unpack(">IBH", first[:7])
                cmd &= 0x7F
                if skip_keepalive and cmd == ctaphid.CMD_KEEPALIVE:
                    continue
                data = bytearray(first[7:])
                while len(data) < length:
                    while not self.packets:
                        self.cond.wait(1)
                    data.extend(self.packets.pop(0)[5:])
                return cid, cmd, bytes(data[:length])


class EchoAuthenticator:
    def __init__(self):
        self.release = threading.Event()
        self.release.set()

    def process(self, data, request):
        while not self.release.wait(0.01):
            if request.cancel.is_set():
                return b"\x2d"
        return b"\x00" + data


def make():
    out = Collector()
    auth = EchoAuthenticator()
    dev = ctaphid.CtapHidDevice(auth, out)
    return dev, out, auth


def send(dev, cid, cmd, data):
    for packet in ctaphid.frame(cid, cmd, data):
        dev.handle_report(packet)


def init(dev, out):
    nonce = os.urandom(8)
    send(dev, ctaphid.BROADCAST_CID, ctaphid.CMD_INIT, nonce)
    cid, cmd, data = out.message()
    assert cid == ctaphid.BROADCAST_CID and cmd == ctaphid.CMD_INIT
    assert data[:8] == nonce
    assert data[12] == 2  # protocol version
    assert data[16] & ctaphid.CAPABILITY_CBOR
    assert data[16] & ctaphid.CAPABILITY_NMSG
    return struct.unpack(">I", data[8:12])[0]


def test_init_allocates_channels():
    dev, out, _ = make()
    a = init(dev, out)
    b = init(dev, out)
    assert a != b
    assert a not in (0, ctaphid.BROADCAST_CID)


def test_ping_large_message():
    dev, out, _ = make()
    cid = init(dev, out)
    payload = os.urandom(1000)
    send(dev, cid, ctaphid.CMD_PING, payload)
    assert out.message() == (cid, ctaphid.CMD_PING, payload)


def test_unknown_channel_rejected():
    dev, out, _ = make()
    send(dev, 0x12345678, ctaphid.CMD_PING, b"x")
    assert out.message() == (0x12345678, ctaphid.CMD_ERROR, bytes([ctaphid.ERR_INVALID_CHANNEL]))


def test_msg_not_supported():
    dev, out, _ = make()
    cid = init(dev, out)
    send(dev, cid, ctaphid.CMD_MSG, b"\x00\x01\x00\x00")
    assert out.message() == (cid, ctaphid.CMD_ERROR, bytes([ctaphid.ERR_INVALID_CMD]))


def test_cbor_with_keepalive_and_busy_and_cancel():
    dev, out, auth = make()
    cid = init(dev, out)
    other = init(dev, out)
    auth.release.clear()
    send(dev, cid, ctaphid.CMD_CBOR, b"\x04")
    time.sleep(0.25)
    # Keepalives flow while the request is pending.
    _, cmd, data = out.message(skip_keepalive=False)
    assert cmd == ctaphid.CMD_KEEPALIVE and data == b"\x01"
    # A second channel is told the device is busy.
    send(dev, other, ctaphid.CMD_CBOR, b"\x04")
    assert out.message() == (other, ctaphid.CMD_ERROR, bytes([ctaphid.ERR_CHANNEL_BUSY]))
    # Cancelling ends the request with KEEPALIVE_CANCEL.
    send(dev, cid, ctaphid.CMD_CANCEL, b"")
    assert out.message() == (cid, ctaphid.CMD_CBOR, b"\x2d")
    auth.release.set()
    send(dev, other, ctaphid.CMD_CBOR, b"\x04")
    assert out.message() == (other, ctaphid.CMD_CBOR, b"\x00\x04")


def test_bad_sequence():
    dev, out, _ = make()
    cid = init(dev, out)
    packets = ctaphid.frame(cid, ctaphid.CMD_PING, os.urandom(200))
    dev.handle_report(packets[0])
    dev.handle_report(packets[2])  # skip seq 0
    assert out.message() == (cid, ctaphid.CMD_ERROR, bytes([ctaphid.ERR_INVALID_SEQ]))


def test_message_timeout():
    dev, out, _ = make()
    cid = init(dev, out)
    packets = ctaphid.frame(cid, ctaphid.CMD_PING, os.urandom(200))
    dev.handle_report(packets[0])  # and then nothing
    assert out.message(timeout=2) == (cid, ctaphid.CMD_ERROR, bytes([ctaphid.ERR_MSG_TIMEOUT]))


def test_channel_table_is_bounded():
    dev, out, _ = make()
    first = init(dev, out)
    for _ in range(ctaphid.MAX_CHANNELS):
        init(dev, out)
    send(dev, first, ctaphid.CMD_PING, b"x")
    assert out.message() == (first, ctaphid.CMD_ERROR, bytes([ctaphid.ERR_INVALID_CHANNEL]))
