"""Symmetric primitives and encodings from the psst-secret format spec."""

import base64
import binascii
import hashlib
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import PsstError

KEY_SIZE = 32
IV_SIZE = 12
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000
RECEIVE_HKDF_SALT = bytes(32)
RECEIVE_HKDF_INFO = b"psst-receive-v2"


class DecryptionError(PsstError):
    pass


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PsstError("Invalid base64 value") from exc


def random_key() -> bytes:
    return os.urandom(KEY_SIZE)


def random_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def encrypt(
    key: bytes, plaintext: bytes, iv: bytes | None = None
) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt. Returns (iv, ciphertext || tag)."""
    if iv is None:
        iv = os.urandom(IV_SIZE)
    return iv, AESGCM(key).encrypt(iv, plaintext, None)


def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise DecryptionError("Invalid key length")
    try:
        return AESGCM(key).decrypt(iv, ciphertext, None)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError(
            "Decryption failed: wrong key or password, or corrupted data"
        ) from exc


def derive_password_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_receive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=RECEIVE_HKDF_SALT,
        info=RECEIVE_HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def new_reveal_token() -> str:
    return secrets.token_hex(32)


def reveal_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def fingerprint(public_key: bytes) -> str:
    return b64encode(hashlib.sha256(public_key).digest())
