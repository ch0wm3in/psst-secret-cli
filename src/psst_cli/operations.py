"""High-level send, request, submit and reveal flows."""

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel

from . import FORMAT_VERSION, READABLE_FORMAT_VERSIONS, PsstError, crypto, xwing
from .api import (
    ApiError,
    ApiInfo,
    Client,
    CreateRequest,
    CreateWhisper,
    Expiry,
    RevealWhisperResponse,
    SubmitWhisper,
    WhisperStatus,
)
from .links import (
    UnsupportedVersionError,
    ViewLink,
    build_submit_fragment,
    build_view_fragment,
    parse_submit_link,
    with_fragment,
)


class PasswordRequiredError(PsstError):
    pass


class NotSubmittedError(PsstError):
    pass


class FingerprintMismatchError(PsstError):
    pass


class UnsupportedOptionError(PsstError):
    pass


class SignInRequiredError(PsstError):
    pass


def _require_sign_in(client: Client, required: bool, action: str) -> None:
    if required and not client.has_token:
        raise SignInRequiredError(
            f"This server requires sign-in to {action}; run `psst login`"
        )


def check_create_options(
    client: Client,
    info: ApiInfo,
    *,
    max_views: int,
    expiry: Expiry,
    notify_email: str,
    creator_only: bool | None = None,
    allowed_reader_emails: list[str] | None = None,
) -> None:
    """Reject options the server does not offer before encrypting or sending anything."""
    _require_sign_in(client, info.auth.login_required, "create whispers")
    if info.limits is not None:
        if max_views > info.limits.max_views:
            raise UnsupportedOptionError(
                f"max views is limited to {info.limits.max_views} on this server"
            )
        if expiry.value not in info.limits.expiry_options:
            options = ", ".join(info.limits.expiry_options)
            raise UnsupportedOptionError(
                f"Expiry {expiry.value} is not offered; choose from {options}"
            )
    if info.features is None:
        return
    if notify_email and not info.features.email_notifications:
        raise UnsupportedOptionError("This server does not send email notifications")
    access = info.features.receive_access
    if creator_only is not None or allowed_reader_emails:
        if not access.enabled:
            raise UnsupportedOptionError(
                "This server does not support reader restrictions"
            )
        if creator_only is False and access.required:
            raise UnsupportedOptionError(
                "This server requires reader restrictions on every request"
            )
        _require_sign_in(client, True, "restrict readers")


def _check_body_size(info: ApiInfo, body: BaseModel) -> None:
    if info.limits is None:
        return
    size = len(body.model_dump_json(exclude_none=True).encode())
    if size > info.limits.max_upload_bytes:
        raise UnsupportedOptionError(
            f"Encrypted payload is {size} bytes; this server accepts at most {info.limits.max_upload_bytes}"
        )


@dataclass(frozen=True)
class ReceiveLinks:
    submit_link: str
    view_link: str
    expires_at: datetime


def send(
    client: Client,
    plaintext: bytes,
    *,
    password: str | None = None,
    max_views: int = 1,
    expiry: Expiry = Expiry.ONE_DAY,
    notify_email: str = "",
    require_auth_view: bool = False,
) -> str:
    info = client.check_compatible(creating=True)
    check_create_options(
        client, info, max_views=max_views, expiry=expiry, notify_email=notify_email
    )
    token = crypto.new_reveal_token()
    if password:
        salt = crypto.random_salt()
        key = crypto.derive_password_key(password, salt)
    else:
        salt = b""
        key = crypto.random_key()
    iv, ciphertext = crypto.encrypt(key, plaintext)
    body = CreateWhisper(
        reveal_token_hash=crypto.reveal_token_hash(token),
        ciphertext=crypto.b64encode(ciphertext),
        iv=crypto.b64encode(iv),
        salt=crypto.b64encode(salt) if salt else "",
        max_views=max_views,
        expiry=expiry,
        notify_email=notify_email,
        require_auth_view=require_auth_view,
    )
    _check_body_size(info, body)
    resp = client.create_whisper(body)
    return with_fragment(
        resp.url, build_view_fragment(token, None if password else key)
    )


def create_request(
    client: Client,
    *,
    password: str | None = None,
    max_views: int = 1,
    expiry: Expiry = Expiry.ONE_DAY,
    notify_email: str = "",
    require_auth_view: bool = False,
    require_auth_submit: bool = False,
    creator_only: bool | None = None,
    allowed_reader_emails: list[str] | None = None,
) -> ReceiveLinks:
    if allowed_reader_emails and creator_only is None:
        # Approved readers only apply to restricted requests.
        creator_only = True
    info = client.check_compatible(creating=True)
    check_create_options(
        client,
        info,
        max_views=max_views,
        expiry=expiry,
        notify_email=notify_email,
        creator_only=creator_only,
        allowed_reader_emails=allowed_reader_emails,
    )
    token = crypto.new_reveal_token()
    seed = crypto.random_key()
    public_key = xwing.public_key_from_seed(seed)
    salt = wrapped_key = wrapped_iv = ""
    if password:
        raw_salt = crypto.random_salt()
        iv, wrapped = crypto.encrypt(
            crypto.derive_password_key(password, raw_salt), seed
        )
        salt, wrapped_key, wrapped_iv = (
            crypto.b64encode(x) for x in (raw_salt, wrapped, iv)
        )
    resp = client.create_request(
        CreateRequest(
            reveal_token_hash=crypto.reveal_token_hash(token),
            public_key=crypto.b64encode(public_key),
            salt=salt,
            wrapped_key=wrapped_key,
            wrapped_key_iv=wrapped_iv,
            max_views=max_views,
            expiry=expiry,
            notify_email=notify_email,
            require_auth_view=require_auth_view,
            require_auth_submit=require_auth_submit,
            creator_only=creator_only,
            allowed_reader_emails=allowed_reader_emails or None,
        )
    )
    return ReceiveLinks(
        submit_link=with_fragment(
            resp.submit_url, build_submit_fragment(crypto.fingerprint(public_key))
        ),
        view_link=with_fragment(
            resp.view_url, build_view_fragment(token, None if password else seed)
        ),
        expires_at=resp.expires_at,
    )


def submit(link: str, plaintext: bytes, *, client: Client | None = None) -> None:
    parsed = parse_submit_link(link)
    client = client or Client(parsed.server)
    info = client.check_compatible(creating=True)
    if info.policies is not None:
        _require_sign_in(client, info.policies.submit_requires_auth, "submit")
    key_resp = client.get_submit_key(parsed.request_id)
    if key_resp.v not in READABLE_FORMAT_VERSIONS:
        raise UnsupportedVersionError(
            f"Request uses unsupported format version {key_resp.v}"
        )
    public_key = crypto.b64decode(key_resp.public_key)
    if not hmac.compare_digest(hashlib.sha256(public_key).digest(), parsed.fingerprint):
        raise FingerprintMismatchError(
            "The server's public key does not match the link fingerprint; not submitting"
        )
    shared_secret, encapsulated_key = xwing.encapsulate(public_key)
    iv, ciphertext = crypto.encrypt(crypto.derive_receive_key(shared_secret), plaintext)
    body = SubmitWhisper(
        v=FORMAT_VERSION,
        ciphertext=crypto.b64encode(ciphertext),
        iv=crypto.b64encode(iv),
        encapsulated_key=crypto.b64encode(encapsulated_key),
    )
    _check_body_size(info, body)
    result = client.submit(parsed.request_id, body)
    if not result.success:
        raise PsstError("The server did not accept the submission")


def needs_password(link: ViewLink) -> bool:
    return link.key is None


def reveal(
    link: ViewLink, *, password: str | None = None, client: Client | None = None
) -> bytes:
    """Fetch and decrypt a whisper. Consumes a view on the server."""
    if needs_password(link) and not password:
        raise PasswordRequiredError("This whisper is password protected")
    client = client or Client(link.server)
    info = client.check_compatible(creating=False)
    if info.policies is not None:
        _require_sign_in(client, info.policies.view_requires_auth, "reveal")
    _ensure_submitted(client, link.view_id)
    resp = client.reveal(link.view_id, link.reveal_token)
    if resp.v not in READABLE_FORMAT_VERSIONS:
        raise UnsupportedVersionError(
            f"Whisper uses unsupported format version {resp.v}"
        )
    if not resp.ciphertext:
        raise NotSubmittedError("Nothing has been submitted to this request yet")
    key = _content_key(resp, link, password)
    return crypto.decrypt(
        key, crypto.b64decode(resp.iv), crypto.b64decode(resp.ciphertext)
    )


def request_status(link: ViewLink, *, client: Client | None = None) -> WhisperStatus:
    """Check a receive request without consuming a view. Send-mode whispers report as gone."""
    client = client or Client(link.server)
    try:
        return client.status(link.view_id)
    except ApiError as exc:
        if exc.status in (404, 410):
            return WhisperStatus(status="gone")
        raise


def _ensure_submitted(client: Client, view_id: str) -> None:
    # Avoids spending a view on a receive request that is still pending.
    try:
        status = client.status(view_id)
    except PsstError:
        return
    if status.status == "pending":
        raise NotSubmittedError("Nothing has been submitted to this request yet")


def _content_key(
    resp: RevealWhisperResponse, link: ViewLink, password: str | None
) -> bytes:
    if resp.encapsulated_key:
        if resp.wrapped_key:
            if not password:
                raise PasswordRequiredError("This request is password protected")
            wrapping_key = crypto.derive_password_key(
                password, crypto.b64decode(resp.salt)
            )
            seed = crypto.decrypt(
                wrapping_key,
                crypto.b64decode(resp.wrapped_key_iv),
                crypto.b64decode(resp.wrapped_key),
            )
        elif link.key is not None:
            seed = link.key
        else:
            raise PsstError("Link is missing the private key")
        return crypto.derive_receive_key(
            xwing.decapsulate(seed, crypto.b64decode(resp.encapsulated_key))
        )
    if resp.salt:
        if not password:
            raise PasswordRequiredError("This whisper is password protected")
        return crypto.derive_password_key(password, crypto.b64decode(resp.salt))
    if link.key is None:
        raise PsstError("Link is missing the decryption key")
    return link.key
