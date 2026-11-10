"""API token sign-in: loopback redirect with PKCE (RFC 8252, RFC 7636)."""

import base64
import hashlib
import hmac
import secrets
import subprocess  # nosec B404
import sys
import time
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from . import PsstError
from .api import Client, TokenExchange, TokenResponse

CLIENT_NAME = "psst CLI"
CALLBACK_PATH = "/callback"
MANUAL_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
LOGIN_TIMEOUT = 300

_CALLBACK_PAGE = (
    "<!doctype html><meta charset=utf-8><title>psst CLI</title>"
    "<p>{message} You can close this window and return to the terminal.</p>"
)


class LoginError(PsstError):
    pass


def is_wsl() -> bool:
    """Whether we are running in Windows Subsystem for Linux (and not in a container there)."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as f:
            proc_version = f.read().lower()
        with open("/proc/1/cgroup", encoding="utf-8", errors="replace") as f:
            cgroup = f.read().lower()
    except OSError:
        return False
    in_container = "/docker/" in cgroup or "/lxc/" in cgroup
    return "microsoft" in proc_version and not in_container


def open_browser(url: str) -> None:
    """Open ``url`` in the user's browser, using the Windows browser under WSL."""
    if is_wsl():
        try:
            subprocess.Popen(  # nosec B603 B607
                ["cmd.exe", "/c", "start", url.replace("&", "^&")],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except OSError:
            pass
    webbrowser.open(url)


def new_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    )
    return verifier, challenge.rstrip(b"=").decode("ascii")


def authorize_url(
    server: str, redirect_uri: str, challenge: str, state: str, scope: str | None
) -> str:
    params = {
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "client_name": CLIENT_NAME,
    }
    if scope:
        params["scope"] = scope
    return f"{server}/cli/authorize?{urlencode(params)}"


class _CallbackServer(HTTPServer):
    result: dict[str, str] | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackServer

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if parts.path != CALLBACK_PATH:
            self.send_error(404)
            return
        self.server.result = {k: v[0] for k, v in parse_qs(parts.query).items()}
        ok = "code" in self.server.result
        body = _CALLBACK_PAGE.format(
            message="Signed in." if ok else "Sign-in was not completed."
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        # The default logger would print the authorization code to stderr.
        pass


def _wait_for_callback(httpd: _CallbackServer, timeout: float) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    while httpd.result is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LoginError("Timed out waiting for the browser sign-in")
        httpd.timeout = remaining
        httpd.handle_request()
    return httpd.result


def login_loopback(
    client: Client,
    *,
    port: int = 0,
    scope: str | None = None,
    open_browser: bool = True,
    show_url: Callable[[str], None] = print,
    timeout: float = LOGIN_TIMEOUT,
) -> TokenResponse:
    verifier, challenge = new_pkce_pair()
    state = secrets.token_urlsafe(32)
    try:
        httpd = _CallbackServer(("127.0.0.1", port), _CallbackHandler)
    except OSError as exc:
        raise LoginError(
            f"Could not listen on 127.0.0.1:{port}: {exc.strerror}"
        ) from exc
    with httpd:
        redirect_uri = f"http://127.0.0.1:{httpd.server_address[1]}{CALLBACK_PATH}"
        url = authorize_url(client.server, redirect_uri, challenge, state, scope)
        show_url(url)
        if open_browser:
            open_browser(url)
        result = _wait_for_callback(httpd, timeout)

    if not hmac.compare_digest(result.get("state", ""), state):
        raise LoginError("Sign-in response had an invalid state; aborting")
    if "error" in result:
        raise LoginError(f"Sign-in failed: {result['error']}")
    if "code" not in result:
        raise LoginError("Sign-in response did not contain a code")
    return client.exchange_token(
        TokenExchange(
            code=result["code"], code_verifier=verifier, redirect_uri=redirect_uri
        )
    )


def login_manual(
    client: Client,
    *,
    read_code: Callable[[], str],
    scope: str | None = None,
    show_url: Callable[[str], None] = print,
) -> TokenResponse:
    verifier, challenge = new_pkce_pair()
    state = secrets.token_urlsafe(32)
    show_url(authorize_url(client.server, MANUAL_REDIRECT_URI, challenge, state, scope))
    code = read_code().strip()
    if not code:
        raise LoginError("No code entered")
    return client.exchange_token(
        TokenExchange(
            code=code, code_verifier=verifier, redirect_uri=MANUAL_REDIRECT_URI
        )
    )
