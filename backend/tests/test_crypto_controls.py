import hashlib
import json
import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.clients import canonical_json


def test_aes_256_gcm_round_trip_and_unique_nonces():
    key = AESGCM.generate_key(bit_length=256)
    cipher = AESGCM(key)
    aad = b"customer:example:v1"
    nonces = [os.urandom(12) for _ in range(100)]
    assert len(set(nonces)) == len(nonces)
    encrypted = cipher.encrypt(nonces[0], b"synthetic private data", aad)
    assert cipher.decrypt(nonces[0], encrypted, aad) == b"synthetic private data"


def test_aes_gcm_rejects_ciphertext_and_metadata_tampering():
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, b"payload", b"record:1")
    tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    with pytest.raises(Exception):
        AESGCM(key).decrypt(nonce, tampered, b"record:1")
    with pytest.raises(Exception):
        AESGCM(key).decrypt(nonce, encrypted, b"record:2")
    with pytest.raises(Exception):
        AESGCM(AESGCM.generate_key(bit_length=256)).decrypt(nonce, encrypted, b"record:1")


def test_ecdsa_p384_signature_rejects_modified_receipt():
    private_key = ec.generate_private_key(ec.SECP384R1())
    receipt = canonical_json({"amount_minor": 100_00, "currency": "LKR", "id": "tx-1"})
    signature = private_key.sign(receipt, ec.ECDSA(hashes.SHA384()))
    private_key.public_key().verify(signature, receipt, ec.ECDSA(hashes.SHA384()))
    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(
            signature,
            canonical_json({"amount_minor": 900_00, "currency": "LKR", "id": "tx-1"}),
            ec.ECDSA(hashes.SHA384()),
        )


def test_sha256_hash_chain_detects_reordering():
    previous = "0" * 64
    chain = []
    for action in ("login", "transfer.prepare", "transfer.commit"):
        body = canonical_json({"action": action, "previous_hash": previous})
        digest = hashlib.sha256(body).hexdigest()
        chain.append((action, previous, digest))
        previous = digest
    assert chain[2][1] == chain[1][2]
    assert chain[2][1] != chain[0][2]


def test_canonical_json_is_stable():
    left = canonical_json({"b": 2, "a": {"d": 4, "c": 3}})
    right = canonical_json({"a": {"c": 3, "d": 4}, "b": 2})
    assert left == right

