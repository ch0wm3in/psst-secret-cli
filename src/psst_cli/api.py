"""HTTP client for the psst-secret /api/v1/ endpoints."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

import requests
from pydantic import BaseModel, Field, ValidationError

from . import API_VERSION, FORMAT_VERSION, PsstError

DEFAULT_TIMEOUT = 30


class Expiry(StrEnum):
    FIVE_MINUTES = "5m"
    ONE_HOUR = "1h"
    ONE_DAY = "1d"
    ONE_WEEK = "1w"
    ONE_MONTH = "1M"


class ApiError(PsstError):
    def __init__(self, status: int, message: str):
        super().__init__(f"Server returned {status}: {message}")
        self.status = status


class IncompatibleServerError(PsstError):
    pass


class ApiInfoAuth(BaseModel):
    login_required: bool
    loopback_pkce: bool
    manual_code: bool
    scopes: list[str]


class ApiInfoReceiveAccess(BaseModel):
    enabled: bool
    default: bool
    required: bool


class ApiInfoFeatures(BaseModel):
    email_notifications: bool
    receive_access: ApiInfoReceiveAccess
    receive_history: bool
    rich_text: bool


class ApiInfoPolicies(BaseModel):
    view_requires_auth: bool
    submit_requires_auth: bool


class ApiInfoLimits(BaseModel):
    max_upload_bytes: int
    max_views: int
    expiry_options: list[str]


class ApiInfo(BaseModel):
    server_version: str
    api_version: int
    format_versions: list[int]
    auth: ApiInfoAuth
    # Added in psst-secret v1.5.2; None on older servers.
    features: ApiInfoFeatures | None = None
    policies: ApiInfoPolicies | None = None
    limits: ApiInfoLimits | None = None


class CreateWhisper(BaseModel):
    v: Literal[1] = FORMAT_VERSION
    reveal_token_hash: str
    ciphertext: str
    iv: str
    salt: str = ""
    max_views: int = Field(default=1, ge=0, le=100)
    expiry: Expiry = Expiry.ONE_DAY
    require_auth_view: bool = False
    notify_email: str = ""


class CreateWhisperResponse(BaseModel):
    id: str
    url: str


class CreateRequest(BaseModel):
    v: Literal[1] = FORMAT_VERSION
    reveal_token_hash: str
    public_key: str
    salt: str = ""
    wrapped_key: str = ""
    wrapped_key_iv: str = ""
    max_views: int = Field(default=1, ge=0, le=100)
    expiry: Expiry = Expiry.ONE_DAY
    require_auth_view: bool = False
    require_auth_submit: bool = False
    notify_email: str = ""
    # None lets the server apply its default.
    creator_only: bool | None = None
    allowed_reader_emails: list[str] | None = Field(default=None, max_length=20)


class CreateRequestResponse(BaseModel):
    id: str
    submit_url: str
    view_url: str
    expires_at: datetime


class SubmitRequestKey(BaseModel):
    public_key: str
    v: int = 0


class SubmitWhisper(BaseModel):
    v: Literal[1] = FORMAT_VERSION
    ciphertext: str
    iv: str
    encapsulated_key: str


class SubmitWhisperResponse(BaseModel):
    success: bool


class _RevealBody(BaseModel):
    reveal_token: str


class RevealWhisperResponse(BaseModel):
    v: int = 0
    ciphertext: str
    iv: str
    salt: str = ""
    encapsulated_key: str = ""
    wrapped_key: str = ""
    wrapped_key_iv: str = ""
    view_count: int
    max_views: int
    remaining_views: int


class WhisperStatus(BaseModel):
    status: Literal["pending", "submitted", "gone"]
    expires_at: datetime | None = None
    view_count: int | None = None
    max_views: int | None = None
    remaining_views: int | None = None


class TokenExchange(BaseModel):
    code: str
    code_verifier: str
    redirect_uri: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    expires_at: datetime
    scope: str


def normalize_server_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise PsstError("Server URL must start with http:// or https://")
    if "#" in url or "?" in url:
        raise PsstError("Server URL must not contain a query or fragment")
    return url


class Client:
    def __init__(
        self, server: str, token: str | None = None, timeout: float = DEFAULT_TIMEOUT
    ):
        self.server = normalize_server_url(server)
        self.timeout = timeout
        self._info: ApiInfo | None = None
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    @property
    def has_token(self) -> bool:
        return "Authorization" in self.session.headers

    def _send(
        self, method: str, path: str, body: BaseModel | None = None
    ) -> requests.Response:
        url = f"{self.server}/api/v1/{path}"
        try:
            resp = self.session.request(
                method,
                url,
                json=(
                    body.model_dump(mode="json", exclude_none=True)
                    if body is not None
                    else None
                ),
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise PsstError(
                f"Could not reach {self.server}: {exc.__class__.__name__}"
            ) from exc
        if not resp.ok:
            try:
                message = resp.json().get("error") or resp.reason
            except ValueError, AttributeError:
                message = resp.reason
            raise ApiError(resp.status_code, str(message))
        return resp

    def _request[T: BaseModel](
        self,
        method: str,
        path: str,
        response_model: type[T],
        body: BaseModel | None = None,
    ) -> T:
        resp = self._send(method, path, body)
        try:
            return response_model.model_validate_json(resp.content)
        except ValidationError as exc:
            raise PsstError(
                f"Unexpected response from {self.server}/api/v1/{path}"
            ) from exc

    def info(self) -> ApiInfo:
        if self._info is None:
            self._info = self._request("GET", "info", ApiInfo)
        return self._info

    def check_compatible(self, *, creating: bool) -> ApiInfo:
        """Verify the server speaks API v1 and, when creating, accepts our format version."""
        info = self.info()
        if info.api_version != API_VERSION:
            raise IncompatibleServerError(
                f"Server API version {info.api_version} is not supported (expected {API_VERSION})"
            )
        if creating and FORMAT_VERSION not in info.format_versions:
            raise IncompatibleServerError(
                f"Server does not accept format version {FORMAT_VERSION} "
                f"(accepts {info.format_versions})"
            )
        return info

    def create_whisper(self, body: CreateWhisper) -> CreateWhisperResponse:
        return self._request("POST", "whisper", CreateWhisperResponse, body)

    def create_request(self, body: CreateRequest) -> CreateRequestResponse:
        return self._request("POST", "whisper/request", CreateRequestResponse, body)

    def get_submit_key(self, request_id: str) -> SubmitRequestKey:
        return self._request("GET", f"whisper/submit/{request_id}", SubmitRequestKey)

    def submit(self, request_id: str, body: SubmitWhisper) -> SubmitWhisperResponse:
        return self._request(
            "POST", f"whisper/submit/{request_id}", SubmitWhisperResponse, body
        )

    def reveal(self, view_id: str, reveal_token: str | None) -> RevealWhisperResponse:
        body = _RevealBody(reveal_token=reveal_token or "")
        return self._request(
            "POST", f"whisper/{view_id}/reveal", RevealWhisperResponse, body
        )

    def status(self, view_id: str) -> WhisperStatus:
        return self._request("GET", f"whisper/{view_id}/status", WhisperStatus)

    def exchange_token(self, body: TokenExchange) -> TokenResponse:
        return self._request("POST", "cli/token", TokenResponse, body)

    def revoke_token(self) -> None:
        self._send("POST", "cli/revoke")
