"""ESP-IDF Security 1 session crypto: Curve25519 + AES-256-CTR."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..errors import CutterError


def generate_keypair() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def public_bytes(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_shared_secret(private_key: X25519PrivateKey, device_pubkey: bytes) -> bytes:
    if len(device_pubkey) != 32:
        raise CutterError(f"device public key must be 32 bytes, got {len(device_pubkey)}")
    try:
        peer = X25519PublicKey.from_public_bytes(device_pubkey)
    except ValueError as exc:
        raise CutterError(f"invalid device public key: {exc}") from exc
    return private_key.exchange(peer)


class SessionCrypto:
    """A single keystream shared by both directions.

    AES-CTR is symmetric, and the device and client both continue the same
    counter across every request/response pair, applying the keystream to each
    buffer in order.
    """

    def __init__(self, shared_secret: bytes, nonce: bytes) -> None:
        if len(shared_secret) != 32:
            raise CutterError(f"session key must be 32 bytes, got {len(shared_secret)}")
        if len(nonce) != 16:
            raise CutterError(f"session nonce must be 16 bytes, got {len(nonce)}")
        self._context = Cipher(algorithms.AES(shared_secret), modes.CTR(nonce)).encryptor()

    def apply(self, data: bytes) -> bytes:
        return self._context.update(data)
