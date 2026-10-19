"""CTAPHID transport: framing, channels and keepalives over 64-byte reports."""

import logging
import os
import struct
import threading
import time

from . import ctap2

log = logging.getLogger(__name__)

PACKET_SIZE = 64
INIT_DATA = PACKET_SIZE - 7
CONT_DATA = PACKET_SIZE - 5
MAX_MESSAGE = INIT_DATA + 128 * CONT_DATA  # 7609 bytes
BROADCAST_CID = 0xFFFFFFFF
TRANSACTION_TIMEOUT = 0.5  # seconds between packets of one message
KEEPALIVE_INTERVAL = 0.1

CMD_PING = 0x01
CMD_MSG = 0x03
CMD_LOCK = 0x04
CMD_INIT = 0x06
CMD_WINK = 0x08
CMD_CBOR = 0x10
CMD_CANCEL = 0x11
CMD_KEEPALIVE = 0x3B
CMD_ERROR = 0x3F

ERR_INVALID_CMD = 0x01
ERR_INVALID_PAR = 0x02
ERR_INVALID_LEN = 0x03
ERR_INVALID_SEQ = 0x04
ERR_MSG_TIMEOUT = 0x05
ERR_CHANNEL_BUSY = 0x06
ERR_LOCK_REQUIRED = 0x0A
ERR_INVALID_CHANNEL = 0x0B
ERR_OTHER = 0x7F

CAPABILITY_WINK = 0x01
CAPABILITY_CBOR = 0x04
CAPABILITY_NMSG = 0x08

PROTOCOL_VERSION = 2
DEVICE_VERSION = (0, 1, 0)


def frame(cid, cmd, data):
    """Split a message into 64-byte CTAPHID reports."""
    packets = []
    header = struct.pack(">IBH", cid, 0x80 | cmd, len(data))
    chunk, rest = data[:INIT_DATA], data[INIT_DATA:]
    packets.append((header + chunk).ljust(PACKET_SIZE, b"\0"))
    seq = 0
    while rest:
        chunk, rest = rest[:CONT_DATA], rest[CONT_DATA:]
        packets.append((struct.pack(">IB", cid, seq) + chunk).ljust(PACKET_SIZE, b"\0"))
        seq += 1
    return packets


class _Assembly:
    def __init__(self, cid, cmd, length, data):
        self.cid = cid
        self.cmd = cmd
        self.length = length
        self.data = bytearray(data[:length])
        self.seq = 0
        self.touched = time.monotonic()

    @property
    def complete(self):
        return len(self.data) >= self.length


class CtapHidDevice:
    """Transport-agnostic CTAPHID device.

    Feed host->device reports to :meth:`handle_report`; device->host reports
    are passed to ``send_report``. CBOR requests run on a worker thread so
    that keepalives and CANCEL keep working while the user is prompted.
    """

    def __init__(self, authenticator, send_report, on_wink=None):
        self.authenticator = authenticator
        self._send_report = send_report
        self.on_wink = on_wink
        self._send_lock = threading.Lock()
        self._lock = threading.Lock()
        self._channels = set()
        self._assembly = None
        self._busy = None  # (cid, cancel_event, status_holder)
        self._lock_cid = None
        self._lock_until = 0.0

    # -- output -----------------------------------------------------------

    def _send(self, cid, cmd, data):
        with self._send_lock:
            for packet in frame(cid, cmd, data):
                self._send_report(packet)

    def _error(self, cid, code):
        self._send(cid, CMD_ERROR, bytes([code]))

    # -- input ------------------------------------------------------------

    def handle_report(self, report):
        report = bytes(report)
        if len(report) == PACKET_SIZE + 1 and report[0] == 0:
            report = report[1:]  # strip report ID
        if len(report) < 7:
            return
        report = report[:PACKET_SIZE].ljust(PACKET_SIZE, b"\0")
        cid = struct.unpack(">I", report[:4])[0]
        if cid == 0:
            self._error(cid, ERR_INVALID_CHANNEL)
            return

        if report[4] & 0x80:
            cmd = report[4] & 0x7F
            length = struct.unpack(">H", report[5:7])[0]
            self._handle_init_packet(cid, cmd, length, report[7:])
        else:
            self._handle_cont_packet(cid, report[4], report[5:])

    def _handle_init_packet(self, cid, cmd, length, data):
        with self._lock:
            asm = self._assembly
            if asm is not None and time.monotonic() - asm.touched > TRANSACTION_TIMEOUT:
                self._error(asm.cid, ERR_MSG_TIMEOUT)
                asm = self._assembly = None
            if cmd == CMD_INIT:
                if asm is not None and asm.cid == cid:
                    self._assembly = None  # INIT resynchronises the channel
            elif cmd == CMD_CANCEL:
                pass
            elif asm is not None:
                self._error(cid, ERR_CHANNEL_BUSY if asm.cid != cid else ERR_INVALID_SEQ)
                if asm.cid == cid:
                    self._assembly = None
                return
            if length > MAX_MESSAGE:
                self._error(cid, ERR_INVALID_LEN)
                return
            msg = _Assembly(cid, cmd, length, data)
            if not msg.complete:
                self._assembly = msg
                return
        self._dispatch(cid, cmd, bytes(msg.data))

    def _handle_cont_packet(self, cid, seq, data):
        with self._lock:
            asm = self._assembly
            if asm is None or asm.cid != cid:
                return  # spurious continuation packets are ignored
            if seq != asm.seq or seq > 0x7F:
                self._assembly = None
                self._error(cid, ERR_INVALID_SEQ)
                return
            asm.seq += 1
            asm.touched = time.monotonic()
            asm.data.extend(data[: asm.length - len(asm.data)])
            if not asm.complete:
                return
            self._assembly = None
        self._dispatch(asm.cid, asm.cmd, bytes(asm.data))

    # -- commands ---------------------------------------------------------

    def _dispatch(self, cid, cmd, data):
        if cmd == CMD_INIT:
            self._cmd_init(cid, data)
            return
        if cid == BROADCAST_CID:
            self._error(cid, ERR_INVALID_CHANNEL)
            return
        if cid not in self._channels:
            self._error(cid, ERR_INVALID_CHANNEL)
            return
        if cmd == CMD_CANCEL:
            busy = self._busy
            if busy is not None and busy[0] == cid:
                busy[1].set()
            return  # CANCEL never gets a direct response
        if (
            self._lock_cid is not None
            and self._lock_cid != cid
            and time.monotonic() < self._lock_until
        ):
            self._error(cid, ERR_CHANNEL_BUSY)
            return
        if self._busy is not None:
            self._error(cid, ERR_CHANNEL_BUSY)
            return
        if cmd == CMD_PING:
            self._send(cid, CMD_PING, data)
        elif cmd == CMD_WINK:
            if self.on_wink:
                self.on_wink()
            self._send(cid, CMD_WINK, b"")
        elif cmd == CMD_LOCK:
            if len(data) != 1 or data[0] > 10:
                self._error(cid, ERR_INVALID_PAR)
                return
            if data[0] == 0:
                self._lock_cid = None
            else:
                self._lock_cid = cid
                self._lock_until = time.monotonic() + data[0]
            self._send(cid, CMD_LOCK, b"")
        elif cmd == CMD_CBOR:
            if not data:
                self._error(cid, ERR_INVALID_LEN)
                return
            self._start_cbor(cid, data)
        else:
            # CTAPHID_MSG (U2F) is not supported, as advertised by NMSG.
            self._error(cid, ERR_INVALID_CMD)

    def _cmd_init(self, cid, data):
        if len(data) != 8:
            self._error(cid, ERR_INVALID_LEN)
            return
        if cid == BROADCAST_CID:
            while True:
                new_cid = struct.unpack(">I", os.urandom(4))[0]
                if new_cid not in (0, BROADCAST_CID) and new_cid not in self._channels:
                    break
            self._channels.add(new_cid)
        else:
            new_cid = cid
            # INIT on an existing channel aborts any pending transaction on it.
            busy = self._busy
            if busy is not None and busy[0] == cid:
                busy[1].set()
        response = data + struct.pack(
            ">IBBBBB",
            new_cid,
            PROTOCOL_VERSION,
            *DEVICE_VERSION,
            CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG,
        )
        self._send(cid, CMD_INIT, response)

    def _start_cbor(self, cid, data):
        cancel = threading.Event()
        status = [ctap2.STATUS_PROCESSING]
        done = threading.Event()
        done_lock = threading.Lock()
        self._busy = (cid, cancel, status)

        def keepalive(code):
            status[0] = code

        def worker():
            try:
                request = ctap2.Request(cancel=cancel, keepalive=keepalive)
                response = self.authenticator.process(data, request)
            except Exception:
                log.exception("CBOR processing failed")
                response = bytes([ctap2.ERR_OTHER])
            if cancel.is_set() and response[:1] != b"\x00":
                response = bytes([ctap2.ERR_KEEPALIVE_CANCEL])
            with done_lock:
                done.set()
                self._busy = None
                self._send(cid, CMD_CBOR, response)

        def pinger():
            while not done.wait(KEEPALIVE_INTERVAL):
                with done_lock:
                    if done.is_set():
                        return
                    self._send(cid, CMD_KEEPALIVE, bytes([status[0]]))

        threading.Thread(target=worker, name="ctap-cbor", daemon=True).start()
        threading.Thread(target=pinger, name="ctap-keepalive", daemon=True).start()
