"""PIN/UV auth protocols one and two (CTAP 2.1 section 6.5).

This authenticator has no client PIN; the protocols are used for built-in
user verification (getPinUvAuthTokenUsingUvWithPermissions) and for the
hmac-secret extension.
"""

import hmac
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ProtocolError(ValueError):
    pass


def _cose_to_public(cose):
    try:
        if cose[1] != 2 or cose[-1] != 1:
            raise ProtocolError("unsupported key agreement key")
        x, y = cose[-2], cose[-3]
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise ProtocolError("bad key agreement coordinates")
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError(str(e))


class PinUvProtocolOne:
    VERSION = 1

    def kdf(self, z):
        return hashlib.sha256(z).digest()

    def encrypt(self, key, plaintext):
        enc = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).encryptor()
        return enc.update(plaintext) + enc.finalize()

    def decrypt(self, key, ciphertext):
        if len(ciphertext) % 16:
            raise ProtocolError("bad ciphertext length")
        dec = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def authenticate(self, key, message):
        return hmac.new(key[:32], message, hashlib.sha256).digest()[:16]

    def verify(self, key, message, signature):
        return hmac.compare_digest(self.authenticate(key, message), signature)


class PinUvProtocolTwo(PinUvProtocolOne):
    VERSION = 2

    def kdf(self, z):
        def hkdf(info):
            return HKDF(
                algorithm=hashes.SHA256(), length=32, salt=b"\0" * 32, info=info
            ).derive(z)

        return hkdf(b"CTAP2 HMAC key") + hkdf(b"CTAP2 AES key")

    def encrypt(self, key, plaintext):
        iv = os.urandom(16)
        enc = Cipher(algorithms.AES(key[32:]), modes.CBC(iv)).encryptor()
        return iv + enc.update(plaintext) + enc.finalize()

    def decrypt(self, key, ciphertext):
        if len(ciphertext) < 16 or len(ciphertext) % 16:
            raise ProtocolError("bad ciphertext length")
        iv, ct = ciphertext[:16], ciphertext[16:]
        dec = Cipher(algorithms.AES(key[32:]), modes.CBC(iv)).decryptor()
        return dec.update(ct) + dec.finalize()

    def authenticate(self, key, message):
        return hmac.new(key[:32], message, hashlib.sha256).digest()

    def verify(self, key, message, signature):
        return hmac.compare_digest(self.authenticate(key, message), signature)


PROTOCOLS = {1: PinUvProtocolOne(), 2: PinUvProtocolTwo()}


class KeyAgreement:
    """The authenticator's ephemeral ECDH key (regenerated on power-up/reset)."""

    def __init__(self):
        self.regenerate()

    def regenerate(self):
        self._key = ec.generate_private_key(ec.SECP256R1())

    def cose(self):
        nums = self._key.public_key().public_numbers()
        return {
            1: 2,
            3: -25,  # ECDH-ES+HKDF-256
            -1: 1,
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        }

    def shared_secret(self, protocol, peer_cose):
        if not isinstance(peer_cose, dict):
            raise ProtocolError("bad key agreement")
        peer = _cose_to_public(peer_cose)
        z = self._key.exchange(ec.ECDH(), peer)
        return protocol.kdf(z)
