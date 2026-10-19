"""Native messaging host: connects the browser extension to passkeyd.

Browsers start this program when the extension opens its native port and
talk to it over stdin/stdout, each message being JSON preceded by its length
as a 32-bit native-endian integer. Only the extension listed in the host
manifest (allowed_origins / allowed_extensions) can start it.

Requests from the extension:
    {"id": n, "op": "status"}
    {"id": n, "op": "has", "origin": o, "options": {...}}
    {"id": n, "op": "create" | "get", "origin": o, "topOrigin": t, "options": {...}}
    {"id": n, "op": "cancel", "target": m}
Replies: {"id": n, "result": ...} or {"id": n, "error": {"name": ..., "message": ...}}.

``origin`` is set by the extension's background script from the browser's
record of which page sent the request; pages cannot choose it.
"""

import json
import struct
import sys
import threading

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from . import DBUS_INTERFACE, DBUS_NAME, DBUS_PATH  # noqa: E402

WEBAUTHN_ERROR = "io.github.haythmkenway.Passkey.WebAuthn."
# Browsers refuse messages from a host larger than 1 MiB; requests are small.
MAX_MESSAGE = 1024 * 1024


def read_message(stream):
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("=I", header)
    if length > MAX_MESSAGE:
        raise ValueError("message too large")
    data = stream.read(length)
    if len(data) < length:
        return None
    return json.loads(data)


def encode_message(message):
    data = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return struct.pack("=I", len(data)) + data


def error_name(error):
    """The DOMException name for a GLib.Error from the daemon."""
    remote = Gio.DBusError.get_remote_error(error) or ""
    if remote.startswith(WEBAUTHN_ERROR):
        return remote[len(WEBAUTHN_ERROR):]
    # The daemon is missing, starting or cannot open its storage: let the
    # browser handle the request itself.
    return "UnavailableError"


class Host:
    def __init__(self, bus, output):
        self.bus = bus
        self.output = output
        self._write_lock = threading.Lock()
        self._active = set()
        self._active_lock = threading.Lock()

    def send(self, message):
        with self._write_lock:
            self.output.write(encode_message(message))
            self.output.flush()

    def _call(self, method, args, signature, timeout=-1):
        return self.bus.call_sync(
            DBUS_NAME,
            DBUS_PATH,
            DBUS_INTERFACE,
            method,
            GLib.Variant(signature, args) if signature else None,
            None,
            Gio.DBusCallFlags.NONE,
            timeout,
            None,
        ).unpack()

    def handle(self, message):
        mid = message.get("id")
        op = message.get("op")
        try:
            if op == "status":
                (status,) = self._call("GetStatus", None, None)
                result = {"ready": status.get("state") == "ready"}
            elif op == "has":
                (result,) = self._call(
                    "WebAuthnHasCredentials",
                    (message["origin"], json.dumps(message["options"])),
                    "(ss)",
                )
            elif op in ("create", "get"):
                handle = str(mid)
                with self._active_lock:
                    self._active.add(handle)
                try:
                    (text,) = self._call(
                        "WebAuthnCreate" if op == "create" else "WebAuthnGet",
                        (
                            message["origin"],
                            message.get("topOrigin") or "",
                            json.dumps(message["options"]),
                            handle,
                        ),
                        "(ssss)",
                        GLib.MAXINT,  # the user may take a while
                    )
                finally:
                    with self._active_lock:
                        self._active.discard(handle)
                result = json.loads(text)
            elif op == "cancel":
                self.cancel(str(message["target"]))
                result = None
            else:
                raise KeyError(op)
        except GLib.Error as e:
            self.send({"id": mid, "error": {"name": error_name(e), "message": e.message}})
            return
        except (KeyError, TypeError, ValueError) as e:
            self.send({"id": mid, "error": {"name": "TypeError", "message": "bad request: %s" % e}})
            return
        self.send({"id": mid, "result": result})

    def cancel(self, handle):
        try:
            self._call("WebAuthnCancel", (handle,), "(s)")
        except GLib.Error:
            pass

    def cancel_all(self):
        with self._active_lock:
            handles = list(self._active)
        for handle in handles:
            self.cancel(handle)


def main(argv=None):
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    # Anything printed by mistake would corrupt the message stream.
    sys.stdout = sys.stderr
    host = Host(Gio.bus_get_sync(Gio.BusType.SESSION, None), stdout)
    return serve(host, stdin)


def serve(host, stdin):
    workers = []
    while True:
        try:
            message = read_message(stdin)
        except ValueError as e:
            print("linux-passkey native host: %s" % e, file=sys.stderr)
            break
        if message is None:
            break  # the browser closed the port
        if not isinstance(message, dict):
            continue
        # Ceremonies wait for the user, so each request gets its own thread.
        worker = threading.Thread(target=host.handle, args=(message,), daemon=True)
        worker.start()
        workers = [w for w in workers if w.is_alive()] + [worker]
    # The browser closed the port: close any open prompt, then let the
    # remaining requests answer before exiting.
    host.cancel_all()
    for worker in workers:
        worker.join(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
