"""End-to-end tests against a live server, e.g. the ghcr.io/ch0wm3in/psst-secret image."""

import os

import pytest

from psst_cli.api import ApiError, Client
from psst_cli.envelope import parse_envelope, text_envelope
from psst_cli.links import parse_view_link
from psst_cli.operations import (
    NotSubmittedError,
    UnsupportedOptionError,
    create_request,
    request_status,
    reveal,
    send,
    submit,
)

SERVER = os.environ.get("PSST_TEST_SERVER")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not SERVER, reason="PSST_TEST_SERVER is not set"),
]

SECRET = "Æble, čaj, 🔐\nsecond line"


@pytest.fixture
def client() -> Client:
    assert SERVER
    return Client(SERVER)


def _text(plaintext: bytes) -> str | None:
    return parse_envelope(plaintext).text


def test_info(client: Client) -> None:
    info = client.check_compatible(creating=True)
    assert info.api_version == 1
    assert (
        info.features is not None
        and info.policies is not None
        and info.limits is not None
    )
    assert "1d" in info.limits.expiry_options


def test_options_follow_server_capabilities(client: Client) -> None:
    info = client.check_compatible(creating=True)
    assert info.features is not None
    if info.features.email_notifications:
        link = parse_view_link(
            send(client, text_envelope(SECRET), notify_email="me@example.com")
        )
        assert _text(reveal(link, client=client)) == SECRET
    else:
        with pytest.raises(UnsupportedOptionError):
            send(client, text_envelope(SECRET), notify_email="me@example.com")
    if not info.features.receive_access.enabled:
        with pytest.raises(UnsupportedOptionError):
            create_request(client, creator_only=True)


def test_payload_over_upload_limit(client: Client) -> None:
    info = client.check_compatible(creating=True)
    assert info.limits is not None
    with pytest.raises(UnsupportedOptionError):
        send(client, b"x" * info.limits.max_upload_bytes)


def test_per_whisper_auth_options_accepted(client: Client) -> None:
    links = create_request(client, require_auth_submit=False, require_auth_view=False)
    assert links.submit_link and links.view_link


def test_send_and_reveal_burns(client: Client) -> None:
    link = parse_view_link(send(client, text_envelope(SECRET)))
    assert _text(reveal(link, client=client)) == SECRET
    with pytest.raises(ApiError):
        reveal(link, client=client)


def test_send_with_password(client: Client) -> None:
    link = parse_view_link(
        send(client, text_envelope(SECRET), password="hunter2 🔑", max_views=2)
    )
    assert link.key is None
    assert _text(reveal(link, password="hunter2 🔑", client=client)) == SECRET


@pytest.mark.parametrize("password", [None, "request password"])
def test_receive_flow(client: Client, password: str | None) -> None:
    links = create_request(client, password=password)
    view = parse_view_link(links.view_link)
    submit(links.submit_link, text_envelope(SECRET, markdown=True), client=client)
    revealed = parse_envelope(reveal(view, password=password, client=client))
    assert (revealed.text, revealed.format) == (SECRET, "markdown")


def test_request_status_and_pending_reveal(client: Client) -> None:
    links = create_request(client)
    view = parse_view_link(links.view_link)
    assert request_status(view, client=client).status == "pending"
    with pytest.raises(NotSubmittedError):
        reveal(view, client=client)

    submit(links.submit_link, text_envelope(SECRET), client=client)
    status = request_status(view, client=client)
    assert (status.status, status.view_count, status.remaining_views) == (
        "submitted",
        0,
        1,
    )

    assert _text(reveal(view, client=client)) == SECRET
    assert request_status(view, client=client).status == "gone"


def test_send_mode_status_is_gone(client: Client) -> None:
    link = parse_view_link(send(client, text_envelope(SECRET)))
    assert request_status(link, client=client).status == "gone"
    assert _text(reveal(link, client=client)) == SECRET
