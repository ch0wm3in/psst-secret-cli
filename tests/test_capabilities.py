import pytest

from psst_cli.api import ApiInfo, Client, Expiry
from psst_cli.operations import (
    SignInRequiredError,
    UnsupportedOptionError,
    check_create_options,
)

INFO = {
    "server_version": "v1.5.2",
    "api_version": 1,
    "format_versions": [1],
    "auth": {
        "login_required": False,
        "loopback_pkce": True,
        "manual_code": False,
        "scopes": [],
    },
    "features": {
        "email_notifications": False,
        "receive_access": {"enabled": True, "default": False, "required": True},
        "receive_history": True,
        "rich_text": True,
    },
    "policies": {"view_requires_auth": False, "submit_requires_auth": False},
    "limits": {
        "max_upload_bytes": 1000,
        "max_views": 10,
        "expiry_options": ["1h", "1d"],
    },
}


def _check(info: dict, token: str | None = None, **options) -> None:
    defaults = {"max_views": 1, "expiry": Expiry.ONE_DAY, "notify_email": ""}
    client = Client("https://psst.example", token=token)
    check_create_options(client, ApiInfo.model_validate(info), **(defaults | options))


def test_accepts_defaults() -> None:
    _check(INFO)


@pytest.mark.parametrize(
    "options",
    [
        {"max_views": 11},
        {"expiry": Expiry.ONE_WEEK},
        {"notify_email": "me@example.com"},
        {"creator_only": False},
    ],
    ids=["max-views", "expiry", "email-disabled", "access-required"],
)
def test_rejects_unoffered_options(options: dict) -> None:
    with pytest.raises(UnsupportedOptionError):
        _check(INFO, token="psst_x", **options)


def test_reader_restrictions_need_sign_in() -> None:
    with pytest.raises(SignInRequiredError):
        _check(INFO, allowed_reader_emails=["a@example.com"], creator_only=True)
    _check(
        INFO, token="psst_x", allowed_reader_emails=["a@example.com"], creator_only=True
    )


def test_login_required() -> None:
    info = INFO | {"auth": INFO["auth"] | {"login_required": True}}
    with pytest.raises(SignInRequiredError):
        _check(info)


def test_older_server_without_capabilities() -> None:
    legacy = {
        k: INFO[k] for k in ("server_version", "api_version", "format_versions", "auth")
    }
    _check(legacy, notify_email="me@example.com", max_views=50, creator_only=False)
