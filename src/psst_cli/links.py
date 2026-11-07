"""Link fragments: building and parsing view and submit links."""

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from . import FORMAT_VERSION, READABLE_FORMAT_VERSIONS, PsstError
from .crypto import b64decode, b64encode

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_REVEAL_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_PARAM_NAMES = ("v", "reveal", "key", "fp")


class UnsupportedVersionError(PsstError):
    pass


@dataclass(frozen=True)
class ViewLink:
    server: str
    view_id: str
    version: int
    reveal_token: str | None
    key: bytes | None


@dataclass(frozen=True)
class SubmitLink:
    server: str
    request_id: str
    version: int
    fingerprint: bytes


def build_view_fragment(reveal_token: str, key: bytes | None = None) -> str:
    params = {"v": str(FORMAT_VERSION), "reveal": reveal_token}
    if key is not None:
        params["key"] = b64encode(key)
    return urlencode(params)


def build_submit_fragment(fingerprint: str) -> str:
    return urlencode({"v": str(FORMAT_VERSION), "fp": fingerprint})


def with_fragment(url: str, fragment: str) -> str:
    return f"{url.split('#', 1)[0]}#{fragment}"


def _split(link: str) -> tuple[str, str, str]:
    parts = urlsplit(link.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise PsstError("Not a valid http(s) link")
    ids = _UUID_RE.findall(parts.path)
    if not ids:
        raise PsstError("Link does not contain a whisper identifier")
    if not parts.fragment:
        raise PsstError("Link is missing its #fragment")
    return f"{parts.scheme}://{parts.netloc}", ids[-1].lower(), parts.fragment


def _parse_fragment(fragment: str) -> tuple[int, dict[str, str] | None, str | None]:
    """Returns (version, params, legacy_bare_value)."""
    params = {k: v[0] for k, v in parse_qs(fragment, keep_blank_values=True).items()}
    if not any(name in params for name in _PARAM_NAMES):
        return 0, None, unquote(fragment)
    raw_version = params.get("v")
    if raw_version is None:
        version = 0
    elif raw_version.isdigit():
        version = int(raw_version)
    else:
        raise UnsupportedVersionError(f"Unsupported format version: {raw_version!r}")
    if version not in READABLE_FORMAT_VERSIONS:
        raise UnsupportedVersionError(f"Unsupported format version: {version}")
    return version, params, None


def parse_view_link(link: str) -> ViewLink:
    server, view_id, fragment = _split(link)
    version, params, bare = _parse_fragment(fragment)
    if params is None:
        return ViewLink(server, view_id, version, None, b64decode(bare or ""))
    token = params.get("reveal") or None
    if token is not None and not _REVEAL_TOKEN_RE.match(token):
        raise PsstError("Invalid reveal token in link")
    key = b64decode(params["key"]) if params.get("key") else None
    return ViewLink(server, view_id, version, token, key)


def parse_submit_link(link: str) -> SubmitLink:
    server, request_id, fragment = _split(link)
    version, params, bare = _parse_fragment(fragment)
    fp = bare if params is None else params.get("fp")
    if not fp:
        raise PsstError("Submit link is missing its fingerprint")
    return SubmitLink(server, request_id, version, b64decode(fp))
