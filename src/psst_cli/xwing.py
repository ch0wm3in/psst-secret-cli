"""X-Wing hybrid KEM (ML-KEM-768 + X25519), draft-connolly-cfrg-xwing-kem."""

import hashlib

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import PsstError

SEED_SIZE = 32
PUBLIC_KEY_SIZE = 1216
CIPHERTEXT_SIZE = 1120
SHARED_SECRET_SIZE = 32

_MLKEM_PUBLIC_KEY_SIZE = 1184
_MLKEM_CIPHERTEXT_SIZE = 1088
_LABEL = b"\\.//^\\"


def _expand(seed: bytes) -> tuple[MLKEM768PrivateKey, X25519PrivateKey]:
    if len(seed) != SEED_SIZE:
        raise PsstError("Invalid X-Wing private key length")
    expanded = hashlib.shake_256(seed).digest(96)
    return (
        MLKEM768PrivateKey.from_seed_bytes(expanded[:64]),
        X25519PrivateKey.from_private_bytes(expanded[64:]),
    )


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _LABEL).digest()


def public_key_from_seed(seed: bytes) -> bytes:
    sk_m, sk_x = _expand(seed)
    return sk_m.public_key().public_bytes_raw() + sk_x.public_key().public_bytes_raw()


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Returns (shared_secret, ciphertext)."""
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise PsstError("Invalid X-Wing public key length")
    pk_m = MLKEM768PublicKey.from_public_bytes(public_key[:_MLKEM_PUBLIC_KEY_SIZE])
    pk_x_bytes = public_key[_MLKEM_PUBLIC_KEY_SIZE:]
    pk_x = X25519PublicKey.from_public_bytes(pk_x_bytes)

    ek_x = X25519PrivateKey.generate()
    ct_x = ek_x.public_key().public_bytes_raw()
    ss_x = ek_x.exchange(pk_x)
    ss_m, ct_m = pk_m.encapsulate()
    return _combine(ss_m, ss_x, ct_x, pk_x_bytes), ct_m + ct_x


def decapsulate(seed: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) != CIPHERTEXT_SIZE:
        raise PsstError("Invalid X-Wing ciphertext length")
    sk_m, sk_x = _expand(seed)
    ct_m = ciphertext[:_MLKEM_CIPHERTEXT_SIZE]
    ct_x = ciphertext[_MLKEM_CIPHERTEXT_SIZE:]
    ss_m = sk_m.decapsulate(ct_m)
    ss_x = sk_x.exchange(X25519PublicKey.from_public_bytes(ct_x))
    return _combine(ss_m, ss_x, ct_x, sk_x.public_key().public_bytes_raw())
