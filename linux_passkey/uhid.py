"""Virtual FIDO HID device backed by the Linux uhid driver (/dev/uhid).

Browsers see it as an ordinary USB security key: udev's fido_id helper
recognises the FIDO usage page in the report descriptor and grants the
logged-in user access to the resulting /dev/hidraw node.
"""

import errno
import logging
import os
import select
import struct
import threading

log = logging.getLogger(__name__)

UHID_PATH = "/dev/uhid"

UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14

UHID_DATA_MAX = 4096
BUS_USB = 0x03

# struct uhid_event is a u32 type followed by a union whose largest member
# is uhid_create2_req (128 + 64 + 64 + 2 + 2 + 4 * 4 + 4096 bytes).
EVENT_SIZE = 4 + 128 + 64 + 64 + 2 + 2 + 4 * 4 + UHID_DATA_MAX

# pid.codes open-source vendor ID with its test product ID. Browsers find the
# device by its FIDO usage page, not by these numbers; see --usb-id.
VENDOR_ID = 0x1209
PRODUCT_ID = 0x0001

FIDO_REPORT_DESCRIPTOR = bytes(
    [
        0x06, 0xD0, 0xF1,  # Usage Page (FIDO Alliance)
        0x09, 0x01,  # Usage (CTAPHID)
        0xA1, 0x01,  # Collection (Application)
        0x09, 0x20,  #   Usage (Input Report Data)
        0x15, 0x00,  #   Logical Minimum (0)
        0x26, 0xFF, 0x00,  #   Logical Maximum (255)
        0x75, 0x08,  #   Report Size (8)
        0x95, 0x40,  #   Report Count (64)
        0x81, 0x02,  #   Input (Data, Var, Abs)
        0x09, 0x21,  #   Usage (Output Report Data)
        0x15, 0x00,  #   Logical Minimum (0)
        0x26, 0xFF, 0x00,  #   Logical Maximum (255)
        0x75, 0x08,  #   Report Size (8)
        0x95, 0x40,  #   Report Count (64)
        0x91, 0x02,  #   Output (Data, Var, Abs)
        0xC0,  # End Collection
    ]
)


def _pad(text, size):
    return text.encode()[: size - 1].ljust(size, b"\0")


def create2_event(name, phys, uniq, descriptor, vendor=VENDOR_ID, product=PRODUCT_ID):
    body = (
        _pad(name, 128)
        + _pad(phys, 64)
        + _pad(uniq, 64)
        + struct.pack("<HHIIII", len(descriptor), BUS_USB, vendor, product, 0x0100, 0)
        + descriptor.ljust(UHID_DATA_MAX, b"\0")
    )
    return struct.pack("<I", UHID_CREATE2) + body


def input2_event(data):
    return (
        struct.pack("<IH", UHID_INPUT2, len(data)) + data.ljust(UHID_DATA_MAX, b"\0")
    ).ljust(EVENT_SIZE, b"\0")


class UhidError(OSError):
    pass


def _os_family(os_release="/etc/os-release"):
    """The distribution's ID and ID_LIKE words from os-release."""
    words = set()
    try:
        with open(os_release, encoding="utf-8") as f:
            for line in f:
                key, _, value = line.strip().partition("=")
                if key in ("ID", "ID_LIKE"):
                    words.update(value.strip("\"'").split())
    except OSError:
        pass
    return words


def missing_module_hint(path=UHID_PATH, modules="/lib/modules", os_release="/etc/os-release"):
    """Explain how to get /dev/uhid on this system."""
    release = os.uname().release
    if not os.path.isdir(os.path.join(modules, release)):
        # Arch and others remove the old kernel's modules on upgrade.
        return (
            "%s not found: the modules of the running kernel %s are not installed; "
            "if the kernel was just updated, restart the computer" % (path, release)
        )
    module_dir = os.path.join(modules, release, "kernel", "drivers", "hid")
    try:
        has_module = any(n.startswith("uhid.ko") for n in os.listdir(module_dir))
    except OSError:
        has_module = False
    if has_module:
        return "%s not found; run 'sudo modprobe uhid'" % path
    if _os_family(os_release) & {"debian", "ubuntu"}:
        return (
            "%s not found: this kernel has no uhid module; install it with "
            "'sudo apt install linux-modules-extra-%s'" % (path, release)
        )
    if "fedora" in _os_family(os_release):
        return (
            "%s not found: this kernel has no uhid module; install it with "
            "'sudo dnf install kernel-modules-core-%s'" % (path, release)
        )
    return (
        "%s not found: this kernel has no uhid module; install the package of "
        "your distribution that has the uhid kernel module (CONFIG_UHID)" % path
    )


class UhidDevice:
    """Creates the virtual device and pumps reports to/from ``on_output``."""

    def __init__(self, on_output, name="Linux Passkey", path=UHID_PATH, usb_id=None):
        self.on_output = on_output
        self.vendor, self.product = usb_id or (VENDOR_ID, PRODUCT_ID)
        self.name = name
        self.path = path
        self._fd = None
        self._thread = None
        self._stop_r, self._stop_w = os.pipe()
        self._write_lock = threading.Lock()
        self.opened = False
        self.on_state = None  # callback(opened: bool)

    def start(self):
        try:
            self._fd = os.open(self.path, os.O_RDWR | os.O_CLOEXEC)
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EPERM):
                raise UhidError(
                    e.errno,
                    "permission denied opening %s; install the udev rule shipped "
                    "with Linux Passkey and log in again" % self.path,
                )
            if e.errno == errno.ENOENT:
                raise UhidError(e.errno, missing_module_hint(self.path))
            raise
        uniq = os.urandom(6).hex()
        os.write(
            self._fd,
            create2_event(
                self.name,
                "linux-passkey",
                uniq,
                FIDO_REPORT_DESCRIPTOR,
                self.vendor,
                self.product,
            ),
        )
        self._thread = threading.Thread(target=self._loop, name="uhid", daemon=True)
        self._thread.start()
        log.info("virtual FIDO device created via %s", self.path)

    def send(self, report):
        if self._fd is None:
            return
        with self._write_lock:
            try:
                os.write(self._fd, input2_event(bytes(report)))
            except OSError as e:
                log.warning("uhid write failed: %s", e)

    def _set_opened(self, value):
        if self.opened != value:
            self.opened = value
            if self.on_state:
                self.on_state(value)

    def _loop(self):
        poller = select.poll()
        poller.register(self._fd, select.POLLIN)
        poller.register(self._stop_r, select.POLLIN)
        while True:
            for fd, _ in poller.poll():
                if fd == self._stop_r:
                    return
            try:
                event = os.read(self._fd, EVENT_SIZE)
            except InterruptedError:
                continue
            except OSError as e:
                log.error("uhid read failed: %s", e)
                return
            if len(event) < 4:
                continue
            etype = struct.unpack_from("<I", event)[0]
            if etype == UHID_OUTPUT:
                data = event[4 : 4 + UHID_DATA_MAX]
                size = struct.unpack_from("<H", event, 4 + UHID_DATA_MAX)[0]
                try:
                    self.on_output(data[:size])
                except Exception:
                    log.exception("error handling HID output report")
            elif etype == UHID_OPEN:
                self._set_opened(True)
            elif etype == UHID_CLOSE:
                self._set_opened(False)
            elif etype == UHID_GET_REPORT:
                req_id = struct.unpack_from("<I", event, 4)[0]
                reply = struct.pack("<IIHH", UHID_GET_REPORT_REPLY, req_id, errno.EIO, 0)
                self._write_raw(reply.ljust(EVENT_SIZE, b"\0"))
            elif etype == UHID_SET_REPORT:
                req_id = struct.unpack_from("<I", event, 4)[0]
                reply = struct.pack("<IIH", UHID_SET_REPORT_REPLY, req_id, errno.EIO)
                self._write_raw(reply.ljust(EVENT_SIZE, b"\0"))

    def _write_raw(self, data):
        with self._write_lock:
            try:
                os.write(self._fd, data)
            except OSError as e:
                log.warning("uhid write failed: %s", e)

    def stop(self):
        if self._fd is None:
            return
        os.write(self._stop_w, b"x")
        if self._thread:
            self._thread.join(timeout=2)
        try:
            os.write(self._fd, struct.pack("<I", UHID_DESTROY).ljust(EVENT_SIZE, b"\0"))
        except OSError:
            pass
        os.close(self._fd)
        self._fd = None
        log.info("virtual FIDO device destroyed")
