"""Credential key pairs and their COSE representation."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

ES256 = -7
EDDSA = -8
SUPPORTED_ALGORITHMS = (ES256, EDDSA)


def generate(alg):
    if alg == ES256:
        return ec.generate_private_key(ec.SECP256R1())
    if alg == EDDSA:
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError("unsupported algorithm %r" % alg)


def private_bytes(alg, key):
    if alg == ES256:
        return key.private_numbers().private_value.to_bytes(32, "big")
    if alg == EDDSA:
        return key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    raise ValueError("unsupported algorithm %r" % alg)


def load(alg, raw):
    if alg == ES256:
        return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
    if alg == EDDSA:
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    raise ValueError("unsupported algorithm %r" % alg)


def cose_public_key(alg, key):
    pub = key.public_key()
    if alg == ES256:
        nums = pub.public_numbers()
        return {
            1: 2,  # kty: EC2
            3: ES256,
            -1: 1,  # crv: P-256
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        }
    if alg == EDDSA:
        return {
            1: 1,  # kty: OKP
            3: EDDSA,
            -1: 6,  # crv: Ed25519
            -2: pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        }
    raise ValueError("unsupported algorithm %r" % alg)


def sign(alg, key, data):
    if alg == ES256:
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if alg == EDDSA:
        return key.sign(data)
    raise ValueError("unsupported algorithm %r" % alg)
