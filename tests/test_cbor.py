import pytest

from linux_passkey import cbor


@pytest.mark.parametrize(
    "value,encoded",
    [
        (0, "00"),
        (23, "17"),
        (24, "1818"),
        (1000, "1903e8"),
        (-1, "20"),
        (-1000, "3903e7"),
        (b"\x01\x02", "420102"),
        ("a", "6161"),
        ([1, 2], "820102"),
        (True, "f5"),
        (False, "f4"),
        (None, "f6"),
        (2**32, "1b0000000100000000"),
    ],
)
def test_roundtrip(value, encoded):
    assert cbor.encode(value).hex() == encoded
    assert cbor.decode(bytes.fromhex(encoded)) == value


def test_canonical_map_ordering():
    # CTAP2 canonical order: shorter keys first, ints before strings.
    data = cbor.encode({"bb": 1, "a": 2, 3: 3, -1: 4, 10: 5})
    assert cbor.decode(data) == {"bb": 1, "a": 2, 3: 3, -1: 4, 10: 5}
    keys = list(cbor.decode(data).keys())
    assert keys == [3, 10, -1, "a", "bb"]


def test_rejects_trailing_and_truncated():
    with pytest.raises(cbor.CBORError):
        cbor.decode(b"\x00\x00")
    with pytest.raises(cbor.CBORError):
        cbor.decode(b"\x42\x01")
    with pytest.raises(cbor.CBORError):
        cbor.decode(b"\x5f")  # indefinite length


def test_nesting_limit():
    with pytest.raises(cbor.CBORError):
        cbor.decode(b"\x81" * 40 + b"\x00")


def test_matches_fido2_library():
    fido_cbor = pytest.importorskip("fido2.cbor")
    obj = {1: b"x" * 300, 2: {"id": "example.com"}, 3: [-7, -8], "up": True}
    assert cbor.encode(obj) == fido_cbor.encode(obj)
    assert cbor.decode(fido_cbor.encode(obj)) == obj


def test_rejects_duplicate_map_keys():
    with pytest.raises(cbor.CBORError):
        cbor.decode(bytes.fromhex("a201020103"))  # {1: 2, 1: 3}


@pytest.mark.parametrize("data", ["f9", "f900", "fa0000", "fb00000000000000", "d1fa"])
def test_truncated_floats_and_tags(data):
    with pytest.raises(cbor.CBORError):
        cbor.decode(bytes.fromhex(data))


def test_random_bytes_only_raise_cbor_error():
    import random

    rng = random.Random(7)
    for _ in range(50000):
        try:
            cbor.decode(rng.randbytes(rng.randrange(0, 24)))
        except cbor.CBORError:
            pass
