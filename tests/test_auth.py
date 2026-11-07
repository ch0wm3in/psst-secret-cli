import base64
import hashlib
import re
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from psst_cli import auth
from psst_cli.api import TokenExchange, TokenResponse
from psst_cli.config import Config, StoredToken, load_config, save_config

SERVER = "https://psst.example"


class FakeClient:
    server = SERVER

    def __init__(self) -> None:
        self.exchanged: TokenExchange | None = None

    def exchange_token(self, body: TokenExchange) -> TokenResponse:
        self.exchanged = body
        return TokenResponse(
            access_token="psst_test",
            token_type="Bearer",
            expires_in=60,
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
            scope="whisper:create",
        )


def _browser(reply: dict[str, str] | None = None):
    """Simulates the browser being redirected back to the loopback listener."""
    captured: dict[str, str] = {}

    def show_url(url: str) -> None:
        params = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        captured.update(params)
        query = (
            reply
            if reply is not None
            else {"code": "psstc_abc", "state": params["state"]}
        )

        def hit() -> None:
            requests.get(params["redirect_uri"], params=query, timeout=5)

        threading.Thread(target=hit, daemon=True).start()

    return show_url, captured


def test_pkce_pair() -> None:
    verifier, challenge = auth.new_pkce_pair()
    assert re.fullmatch(r"[A-Za-z0-9\-._~]{43,128}", verifier)
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert challenge == expected


def test_loopback_login() -> None:
    client = FakeClient()
    show_url, params = _browser()
    token = auth.login_loopback(client, open_browser=False, show_url=show_url, timeout=10)  # type: ignore[arg-type]
    assert token.access_token == "psst_test"
    assert params["code_challenge_method"] == "S256"
    assert params["client_name"] == auth.CLIENT_NAME
    assert re.fullmatch(r"http://127\.0\.0\.1:\d+/callback", params["redirect_uri"])
    assert client.exchanged is not None
    assert client.exchanged.code == "psstc_abc"
    assert client.exchanged.redirect_uri == params["redirect_uri"]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(client.exchanged.code_verifier.encode()).digest()
    )
    assert challenge.rstrip(b"=").decode() == params["code_challenge"]


@pytest.mark.parametrize(
    "reply",
    [{"code": "psstc_abc", "state": "wrong"}, {"error": "access_denied"}],
    ids=["bad-state", "denied"],
)
def test_loopback_login_rejects(reply: dict[str, str]) -> None:
    client = FakeClient()
    show_url, _ = _browser(reply)
    with pytest.raises(auth.LoginError):
        auth.login_loopback(client, open_browser=False, show_url=show_url, timeout=10)  # type: ignore[arg-type]
    assert client.exchanged is None


def test_manual_login() -> None:
    client = FakeClient()
    urls: list[str] = []
    auth.login_manual(client, read_code=lambda: " psstc_xyz ", show_url=urls.append)  # type: ignore[arg-type]
    assert parse_qs(urlsplit(urls[0]).query)["redirect_uri"] == [
        auth.MANUAL_REDIRECT_URI
    ]
    assert client.exchanged is not None
    assert client.exchanged.code == "psstc_xyz"
    assert client.exchanged.redirect_uri == auth.MANUAL_REDIRECT_URI


def test_config_with_token_is_private(tmp_path: Path) -> None:
    path = tmp_path / "psst" / "config.json"
    expires = datetime.now(UTC) + timedelta(days=1)
    save_config(
        Config(
            tokens={
                SERVER: StoredToken(
                    access_token="psst_x", expires_at=expires, scope="s"
                )
            }
        ),
        path,
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = load_config(path)
    assert loaded.tokens[SERVER].access_token == "psst_x"
    assert not loaded.tokens[SERVER].is_expired()
