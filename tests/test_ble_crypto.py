from __future__ import annotations

from blueair_cloudcutter.ble.crypto import (
    SessionCrypto,
    derive_shared_secret,
    generate_keypair,
    public_bytes,
)


def test_x25519_shared_secret_is_symmetric():
    alice = generate_keypair()
    bob = generate_keypair()
    alice_pub = public_bytes(alice)
    bob_pub = public_bytes(bob)
    assert len(alice_pub) == 32
    assert derive_shared_secret(alice, bob_pub) == derive_shared_secret(bob, alice_pub)


def test_aes_ctr_keystream_is_continuous():
    key = bytes(range(32))
    nonce = bytes(range(16))

    one_shot = SessionCrypto(key, nonce).apply(b"a" * 32)

    split = SessionCrypto(key, nonce)
    first = split.apply(b"a" * 16)
    second = split.apply(b"a" * 16)
    assert first + second == one_shot


def test_aes_ctr_roundtrip():
    key = bytes(range(32))
    nonce = bytes(range(16))
    sender = SessionCrypto(key, nonce)
    receiver = SessionCrypto(key, nonce)
    plaintext = b"the quick brown fox"
    ciphertext = sender.apply(plaintext)
    assert ciphertext != plaintext
    assert receiver.apply(ciphertext) == plaintext
