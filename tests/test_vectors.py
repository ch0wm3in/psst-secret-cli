"""Shared psst-secret test vectors (spec/vectors/v1, pinned to SPEC_VERSION)."""

import json
from pathlib import Path

import pytest

from psst_cli import FORMAT_VERSION, crypto, xwing
from psst_cli.api import RevealWhisperResponse
from psst_cli.envelope import parse_envelope, text_envelope
from psst_cli.links import build_submit_fragment, build_view_fragment, parse_view_link
from psst_cli.operations import _content_key

VECTORS = Path(__file__).parent / "vectors" / "v1"
VIEW_URL = "https://psst.example/whisper/0b7c3c3e-8f4a-4a52-9a43-1f2d3e4f5a6b"


def _cases(mode: str) -> list[dict]:
    data = json.loads((VECTORS / f"{mode}.json").read_text(encoding="utf-8"))
    assert data["format_version"] == FORMAT_VERSION
    assert data["mode"] == mode
    return data["cases"]


def _ids(mode: str) -> list[str]:
    return [case["name"] for case in _cases(mode)]


def _check_plaintext(case: dict, key: bytes) -> None:
    b = crypto.b64decode
    iv, ciphertext = crypto.encrypt(key, case["plaintext"].encode(), iv=b(case["iv"]))
    assert crypto.b64encode(ciphertext) == case["ciphertext"]
    assert crypto.decrypt(key, iv, ciphertext).decode() == case["plaintext"]
    assert crypto.reveal_token_hash(case["reveal_token"]) == case["reveal_token_hash"]


def _check_envelope(plaintext: str) -> None:
    revealed = parse_envelope(plaintext.encode())
    if revealed.text is not None:
        assert (
            text_envelope(
                revealed.text, markdown=revealed.format == "markdown"
            ).decode()
            == plaintext
        )
    else:
        assert revealed.files


def _reveal_response(case: dict, **extra: str) -> RevealWhisperResponse:
    return RevealWhisperResponse(
        v=FORMAT_VERSION,
        ciphertext=case["ciphertext"],
        iv=case["iv"],
        view_count=1,
        max_views=1,
        remaining_views=0,
        **extra,
    )


def _decrypt_via_link(
    case: dict, fragment: str, password: str | None = None, **extra: str
) -> str:
    link = parse_view_link(f"{VIEW_URL}#{fragment}")
    assert link.version == FORMAT_VERSION
    assert link.reveal_token == case["reveal_token"]
    resp = _reveal_response(case, **extra)
    key = _content_key(resp, link, password)
    return crypto.decrypt(
        key, crypto.b64decode(resp.iv), crypto.b64decode(resp.ciphertext)
    ).decode()


@pytest.mark.parametrize("case", _cases("send"), ids=_ids("send"))
def test_send(case: dict) -> None:
    key = crypto.b64decode(case["key"])
    _check_plaintext(case, key)
    _check_envelope(case["plaintext"])
    assert build_view_fragment(case["reveal_token"], key) == case["fragment"]
    assert _decrypt_via_link(case, case["fragment"]) == case["plaintext"]


@pytest.mark.parametrize("case", _cases("password"), ids=_ids("password"))
def test_password(case: dict) -> None:
    assert case["iterations"] == crypto.PBKDF2_ITERATIONS
    key = crypto.derive_password_key(case["password"], crypto.b64decode(case["salt"]))
    _check_plaintext(case, key)
    assert build_view_fragment(case["reveal_token"]) == case["fragment"]
    plaintext = _decrypt_via_link(
        case, case["fragment"], case["password"], salt=case["salt"]
    )
    assert plaintext == case["plaintext"]


@pytest.mark.parametrize("case", _cases("receive"), ids=_ids("receive"))
def test_receive(case: dict) -> None:
    seed = crypto.b64decode(case["seed"])
    public_key = xwing.public_key_from_seed(seed)
    assert crypto.b64encode(public_key) == case["public_key"]
    assert crypto.fingerprint(public_key) == case["fingerprint"]
    assert build_submit_fragment(case["fingerprint"]) == case["submit_fragment"]

    shared_secret = xwing.decapsulate(seed, crypto.b64decode(case["encapsulated_key"]))
    _check_plaintext(case, crypto.derive_receive_key(shared_secret))

    extra = {"encapsulated_key": case["encapsulated_key"]}
    password = case.get("password")
    if password:
        wrapping_key = crypto.derive_password_key(
            password, crypto.b64decode(case["salt"])
        )
        _, wrapped = crypto.encrypt(
            wrapping_key, seed, iv=crypto.b64decode(case["wrapped_key_iv"])
        )
        assert crypto.b64encode(wrapped) == case["wrapped_key"]
        assert build_view_fragment(case["reveal_token"]) == case["view_fragment"]
        extra |= {k: case[k] for k in ("salt", "wrapped_key", "wrapped_key_iv")}
    else:
        assert build_view_fragment(case["reveal_token"], seed) == case["view_fragment"]
    assert (
        _decrypt_via_link(case, case["view_fragment"], password, **extra)
        == case["plaintext"]
    )


def test_xwing_roundtrip() -> None:
    seed = crypto.random_key()
    shared_secret, ciphertext = xwing.encapsulate(xwing.public_key_from_seed(seed))
    assert len(ciphertext) == xwing.CIPHERTEXT_SIZE
    assert xwing.decapsulate(seed, ciphertext) == shared_secret
