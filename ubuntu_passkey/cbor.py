"""Minimal CBOR (RFC 8949) codec covering the subset used by CTAP2.

Encoding follows the CTAP2 canonical form: shortest integer encodings,
definite lengths and map keys sorted by (major type, length, bytes).
"""

import struct


class CBORError(ValueError):
    pass


def _head(major, value):
    if value < 24:
        return bytes([major << 5 | value])
    if value < 0x100:
        return bytes([major << 5 | 24, value])
    if value < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", value)
    if value < 0x100000000:
        return bytes([major << 5 | 26]) + struct.pack(">I", value)
    if value < 0x10000000000000000:
        return bytes([major << 5 | 27]) + struct.pack(">Q", value)
    raise CBORError("integer too large")


def encode(obj):
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if obj is None:
        return b"\xf6"
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        obj = bytes(obj)
        return _head(2, len(obj)) + obj
    if isinstance(obj, str):
        data = obj.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b"".join(encode(x) for x in obj)
    if isinstance(obj, dict):
        items = sorted(
            ((encode(k), encode(v)) for k, v in obj.items()),
            key=lambda kv: (kv[0][0] >> 5, len(kv[0]), kv[0]),
        )
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(obj, float):
        return b"\xfb" + struct.pack(">d", obj)
    raise CBORError("cannot encode %r" % type(obj))


def _read_arg(data, pos, info):
    if info < 24:
        return info, pos
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    if info not in sizes:
        raise CBORError("indefinite or reserved length not supported")
    n = sizes[info]
    if pos + n > len(data):
        raise CBORError("truncated")
    return int.from_bytes(data[pos:pos + n], "big"), pos + n


def _decode(data, pos, depth):
    if depth > 16:
        raise CBORError("nesting too deep")
    if pos >= len(data):
        raise CBORError("truncated")
    initial = data[pos]
    major, info = initial >> 5, initial & 0x1F
    pos += 1
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info in (22, 23):
            return None, pos
        if info == 25:
            return _half(data[pos:pos + 2]), pos + 2
        if info == 26:
            return struct.unpack(">f", data[pos:pos + 4])[0], pos + 4
        if info == 27:
            return struct.unpack(">d", data[pos:pos + 8])[0], pos + 8
        raise CBORError("unsupported simple value")
    arg, pos = _read_arg(data, pos, info)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if pos + arg > len(data):
            raise CBORError("truncated")
        raw = bytes(data[pos:pos + arg])
        pos += arg
        if major == 3:
            try:
                return raw.decode("utf-8"), pos
            except UnicodeDecodeError as e:
                raise CBORError("invalid utf-8") from e
        return raw, pos
    if major == 4:
        out = []
        for _ in range(arg):
            item, pos = _decode(data, pos, depth + 1)
            out.append(item)
        return out, pos
    if major == 5:
        out = {}
        for _ in range(arg):
            key, pos = _decode(data, pos, depth + 1)
            if isinstance(key, (list, dict)):
                raise CBORError("unhashable map key")
            if key in out:
                raise CBORError("duplicate map key")
            out[key], pos = _decode(data, pos, depth + 1)
        return out, pos
    if major == 6:
        # Tags are not used by CTAP2; decode the tagged item and drop the tag.
        return _decode(data, pos, depth + 1)
    raise CBORError("bad major type")


def _half(b):
    if len(b) < 2:
        raise CBORError("truncated")
    h = int.from_bytes(b, "big")
    exp, mant = (h >> 10) & 0x1F, h & 0x3FF
    if exp == 0:
        val = mant * 2.0 ** -24
    elif exp == 31:
        val = float("inf") if mant == 0 else float("nan")
    else:
        val = (mant + 1024) * 2.0 ** (exp - 25)
    return -val if h & 0x8000 else val


def decode(data):
    """Decode a single CBOR item, rejecting trailing bytes."""
    obj, pos = _decode(bytes(data), 0, 0)
    if pos != len(data):
        raise CBORError("trailing data")
    return obj


def decode_from(data):
    """Decode one CBOR item from the front of ``data``; return (item, rest)."""
    obj, pos = _decode(bytes(data), 0, 0)
    return obj, bytes(data[pos:])
