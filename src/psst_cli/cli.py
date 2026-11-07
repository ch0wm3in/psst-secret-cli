"""psst command-line interface."""

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from . import SPEC_VERSION, PsstError, __version__, auth, operations
from .api import ApiError, Client, Expiry, normalize_server_url
from .config import StoredToken, config_path, load_config, save_config
from .envelope import Revealed, files_envelope, parse_envelope, text_envelope
from .links import ViewLink, parse_submit_link, parse_view_link
from .saved import (
    SavedRequest,
    delete_requests,
    load_requests,
    requests_path,
    save_requests,
)

app = typer.Typer(
    help="Share secrets with a psst-secret server. Encryption happens locally.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
config_app = typer.Typer(help="Show or change saved settings.", no_args_is_help=True)
app.add_typer(config_app, name="config")
requests_app = typer.Typer(
    help="Saved receive requests (opt-in, stored only on this machine).",
    no_args_is_help=True,
)
app.add_typer(requests_app, name="requests")


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"psst {__version__} (psst-secret spec {SPEC_VERSION})")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_show_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    pass


@app.command("version")
def version_() -> None:
    """Show the CLI version."""
    _show_version(True)


ServerOption = Annotated[
    str | None,
    typer.Option(
        "--server",
        "-s",
        envvar="PSST_SERVER",
        help="Server URL. Overrides the saved setting.",
    ),
]
PasswordFlag = Annotated[
    bool,
    typer.Option(
        "--password",
        "-p",
        help="Protect with a password (prompted, never an argument).",
    ),
]
MaxViewsOption = Annotated[
    int,
    typer.Option(
        "--max-views",
        min=0,
        max=100,
        help="Reveals before self-destruction; 0 = unlimited.",
    ),
]
ExpiryOption = Annotated[
    Expiry, typer.Option("--expiry", "-e", help="Time until the whisper expires.")
]
FilesOption = Annotated[
    list[Path] | None,
    typer.Option(
        "--file",
        "-f",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Send a file instead of text. Repeatable.",
    ),
]
MarkdownFlag = Annotated[
    bool, typer.Option("--markdown", help="Mark text content as Markdown.")
]
NotifyEmailOption = Annotated[
    str,
    typer.Option(
        "--notify-email", help="Email to notify (recipient for send, you for requests)."
    ),
]
RequireAuthViewFlag = Annotated[
    bool, typer.Option("--require-auth-view", help="Require sign-in to reveal.")
]


@contextmanager
def _user_errors() -> Iterator[None]:
    try:
        yield
    except PsstError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        if isinstance(exc, ApiError) and exc.status == 401:
            typer.echo("Sign in with `psst login`.", err=True)
        raise typer.Exit(1) from None


def _server_url(server: str | None) -> str:
    server = server or load_config().server
    if not server:
        raise PsstError(
            "No server configured. Use --server, PSST_SERVER, or `psst config set-server`."
        )
    return normalize_server_url(server)


def _token_for(server: str) -> str | None:
    if env_token := os.environ.get("PSST_TOKEN"):
        return env_token
    stored = load_config().tokens.get(server)
    if stored is None:
        return None
    if stored.is_expired():
        typer.echo(
            "Your API token has expired; run `psst login` to sign in again.", err=True
        )
        return None
    return stored.access_token


def _client(server: str | None) -> Client:
    url = _server_url(server)
    return Client(url, token=_token_for(url))


def _read_secret(label: str) -> str:
    """Read a secret from piped stdin or a hidden prompt, so it never lands in shell history."""
    if sys.stdin.isatty():
        value = typer.prompt(label, hide_input=True)
    else:
        value = sys.stdin.read().removesuffix("\n")
    if not value:
        raise PsstError(f"{label} is empty")
    return value


def _prompt_new_password() -> str:
    return typer.prompt("Password", hide_input=True, confirmation_prompt=True)


def _payload(files: list[Path] | None, markdown: bool) -> bytes:
    if files:
        return files_envelope(files)
    return text_envelope(_read_secret("Secret"), markdown=markdown)


def _write_files(revealed: Revealed, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for file in revealed.files:
        target = output_dir / file.filename
        stem, suffix = target.stem, target.suffix
        counter = 1
        while True:
            try:
                with target.open("xb") as fh:
                    fh.write(file.data)
                break
            except FileExistsError:
                target = output_dir / f"{stem} ({counter}){suffix}"
                counter += 1
        typer.echo(
            f"Saved {target} ({file.mimetype}, {len(file.data)} bytes)", err=True
        )


@app.command()
def info(server: ServerOption = None) -> None:
    """Show server details and check compatibility with this client."""
    with _user_errors():
        client = _client(server)
        details = client.check_compatible(creating=True)
        typer.echo(f"Server:          {client.server}")
        typer.echo(f"Server version:  {details.server_version}")
        typer.echo(f"API version:     {details.api_version}")
        typer.echo(f"Format versions: {', '.join(map(str, details.format_versions))}")
        typer.echo(f"Login required:  {details.auth.login_required}")
        if details.features is not None:
            access = details.features.receive_access
            access_state = (
                "off"
                if not access.enabled
                else (
                    "required"
                    if access.required
                    else "on by default" if access.default else "available"
                )
            )
            typer.echo(f"Email notify:    {details.features.email_notifications}")
            typer.echo(f"Reader access:   {access_state}")
            typer.echo(f"Saved requests:  {details.features.receive_history}")
            typer.echo(f"Markdown:        {details.features.rich_text}")
        if details.policies is not None:
            typer.echo(
                f"Reveal sign-in:  {'always' if details.policies.view_requires_auth else 'optional'}"
            )
            typer.echo(
                f"Submit sign-in:  {'always' if details.policies.submit_requires_auth else 'optional'}"
            )
        if details.limits is not None:
            typer.echo(f"Max upload:      {details.limits.max_upload_bytes} bytes")
            typer.echo(f"Max views:       {details.limits.max_views}")
            typer.echo(f"Expiry options:  {', '.join(details.limits.expiry_options)}")
        typer.echo(f"Client version:  {__version__}")
        typer.echo(f"Client spec:     {SPEC_VERSION}")
        typer.secho("Compatible", fg=typer.colors.GREEN)


@app.command()
def send(
    server: ServerOption = None,
    files: FilesOption = None,
    password: PasswordFlag = False,
    max_views: MaxViewsOption = 1,
    expiry: ExpiryOption = Expiry.ONE_DAY,
    markdown: MarkdownFlag = False,
    notify_email: NotifyEmailOption = "",
    require_auth_view: RequireAuthViewFlag = False,
) -> None:
    """Encrypt text (from stdin or a prompt) or files and print the share link."""
    with _user_errors():
        client = _client(server)
        info = client.check_compatible(creating=True)
        operations.check_create_options(
            client, info, max_views=max_views, expiry=expiry, notify_email=notify_email
        )
        if markdown and info.features is not None and not info.features.rich_text:
            typer.echo("Note: this server shows Markdown as plain text.", err=True)
        payload = _payload(files, markdown)
        secret_password = _prompt_new_password() if password else None
        link = operations.send(
            client,
            payload,
            password=secret_password,
            max_views=max_views,
            expiry=expiry,
            notify_email=notify_email,
            require_auth_view=require_auth_view,
        )
        typer.echo(link)
        if password:
            typer.echo("Share the password separately.", err=True)


@app.command()
def reveal(
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir", "-o", file_okay=False, help="Where to save revealed files."
        ),
    ] = Path("."),
) -> None:
    """Fetch and decrypt a whisper. The link is read from stdin or a hidden prompt."""
    with _user_errors():
        _reveal_link(parse_view_link(_read_secret("Link")), output_dir)


def _reveal_link(link: ViewLink, output_dir: Path) -> None:
    secret_password = None
    if operations.needs_password(link):
        secret_password = typer.prompt("Password", hide_input=True)
    revealed = parse_envelope(
        operations.reveal(link, password=secret_password, client=_client(link.server))
    )
    if revealed.files:
        _write_files(revealed, output_dir)
    else:
        typer.echo(revealed.text)


@app.command("request")
def request_(
    server: ServerOption = None,
    password: PasswordFlag = False,
    max_views: MaxViewsOption = 1,
    expiry: ExpiryOption = Expiry.ONE_DAY,
    notify_email: NotifyEmailOption = "",
    require_auth_view: RequireAuthViewFlag = False,
    require_auth_submit: Annotated[
        bool, typer.Option("--require-auth-submit", help="Require sign-in to submit.")
    ] = False,
    creator_only: Annotated[
        bool | None,
        typer.Option(
            "--creator-only/--anyone-with-link",
            help="Only you and approved readers can reveal (needs sign-in). Default: server setting.",
        ),
    ] = None,
    readers: Annotated[
        list[str] | None,
        typer.Option(
            "--reader", help="Email of an approved reader. Repeatable, up to 20."
        ),
    ] = None,
    save: Annotated[
        bool | None,
        typer.Option(
            "--save/--no-save",
            help="Keep this request in `psst requests`. Default: on if enabled with `psst config save-requests on`.",
        ),
    ] = None,
    label: Annotated[
        str, typer.Option("--label", "-l", help="Label for the saved request.")
    ] = "",
) -> None:
    """Create a receive request: share the submit link, keep the view link."""
    with _user_errors():
        client = _client(server)
        options = {
            "max_views": max_views,
            "expiry": expiry,
            "notify_email": notify_email,
            "creator_only": True if readers and creator_only is None else creator_only,
            "allowed_reader_emails": readers,
        }
        operations.check_create_options(
            client, client.check_compatible(creating=True), **options
        )
        secret_password = _prompt_new_password() if password else None
        links = operations.create_request(
            client,
            password=secret_password,
            require_auth_view=require_auth_view,
            require_auth_submit=require_auth_submit,
            **options,
        )
        typer.echo(f"Submit link (share this): {links.submit_link}")
        typer.echo(f"View link (keep private): {links.view_link}")
        typer.echo(f"Expires at: {links.expires_at:%Y-%m-%d %H:%M %Z}", err=True)
        if save if save is not None else load_config().save_requests:
            entry = SavedRequest(
                view_id=parse_view_link(links.view_link).view_id,
                label=label,
                submit_link=links.submit_link,
                view_link=links.view_link,
                created_at=datetime.now(UTC),
                expires_at=links.expires_at,
            )
            store = load_requests()
            store.add(entry)
            save_requests(store)
            typer.echo(
                f"Saved as {entry.short_id}{f' ({label})' if label else ''}.", err=True
            )
        elif label:
            typer.echo("Note: --label has no effect without --save.", err=True)


@app.command()
def status() -> None:
    """Check whether a receive request has been submitted, without using a view.

    The view link is read from stdin or a hidden prompt; only its identifier is sent.
    """
    with _user_errors():
        link = parse_view_link(_read_secret("Link"))
        result = operations.request_status(link, client=_client(link.server))
        typer.echo(f"Status:          {result.status}")
        if result.status == "gone":
            typer.echo("The request expired, was burned, or never existed.", err=True)
            raise typer.Exit(1)
        if result.expires_at:
            typer.echo(f"Expires at:      {result.expires_at:%Y-%m-%d %H:%M %Z}")
        if result.max_views is not None:
            remaining = "unlimited" if result.max_views == 0 else result.remaining_views
            typer.echo(
                f"Views:           {result.view_count} used, {remaining} remaining"
            )


@app.command()
def submit(
    link: Annotated[
        str, typer.Argument(help="Submit link received from the requester.")
    ],
    files: FilesOption = None,
    markdown: MarkdownFlag = False,
) -> None:
    """Encrypt text (from stdin or a prompt) or files to a receive request."""
    with _user_errors():
        client = _client(parse_submit_link(link).server)
        operations.submit(link, _payload(files, markdown), client=client)
        typer.secho("Submitted.", fg=typer.colors.GREEN, err=True)


@app.command()
def login(
    server: ServerOption = None,
    manual: Annotated[
        bool,
        typer.Option(
            "--manual",
            help="Paste a code shown in the browser instead of using a local callback.",
        ),
    ] = False,
    port: Annotated[
        int,
        typer.Option(
            "--port",
            min=0,
            max=65535,
            help="Local callback port (e.g. for SSH forwarding); 0 = any.",
        ),
    ] = 0,
    scope: Annotated[
        str | None,
        typer.Option(
            "--scope", help="Space-separated scopes to request. Default: all."
        ),
    ] = None,
    no_browser: Annotated[
        bool, typer.Option("--no-browser", help="Only print the sign-in URL.")
    ] = False,
) -> None:
    """Sign in through the browser and save an API token for this server."""
    with _user_errors():
        client = Client(_server_url(server))
        details = client.check_compatible(creating=False).auth
        if not (details.loopback_pkce or details.manual_code):
            raise PsstError("This server does not offer API token sign-in")
        if manual and not details.manual_code:
            raise PsstError(
                "This server does not allow manual-code sign-in; omit --manual"
            )
        if not manual and not details.loopback_pkce:
            raise PsstError("This server only allows manual-code sign-in; use --manual")

        def show_url(url: str) -> None:
            typer.echo("Open this URL to sign in:", err=True)
            typer.echo(url, err=True)

        if manual:
            token = auth.login_manual(
                client,
                scope=scope,
                show_url=show_url,
                read_code=lambda: typer.prompt("Code", hide_input=True),
            )
        else:
            token = auth.login_loopback(
                client,
                port=port,
                scope=scope,
                open_browser=not no_browser,
                show_url=show_url,
            )
        config = load_config()
        config.tokens[client.server] = StoredToken(
            access_token=token.access_token,
            expires_at=token.expires_at,
            scope=token.scope,
        )
        save_config(config)
        typer.secho(
            f"Signed in to {client.server} (scopes: {token.scope}).",
            fg=typer.colors.GREEN,
            err=True,
        )
        typer.echo(f"Token expires at {token.expires_at:%Y-%m-%d %H:%M %Z}.", err=True)


@app.command()
def logout(server: ServerOption = None) -> None:
    """Revoke and forget the saved API token for this server."""
    with _user_errors():
        url = _server_url(server)
        config = load_config()
        stored = config.tokens.pop(url, None)
        if stored is None:
            typer.echo(f"Not signed in to {url}.", err=True)
            return
        save_config(config)
        try:
            Client(url, token=stored.access_token).revoke_token()
        except PsstError as exc:
            # 401 means the token was already expired or revoked.
            if not (isinstance(exc, ApiError) and exc.status == 401):
                typer.echo(
                    f"Could not revoke the token on the server ({exc}); revoke it at {url}/cli/tokens.",
                    err=True,
                )
        typer.echo(f"Signed out of {url}.", err=True)


@config_app.command("set-server")
def set_server(
    url: Annotated[str, typer.Argument(help="Base URL, e.g. https://psst.example.com")],
) -> None:
    """Save the default server URL."""
    with _user_errors():
        config = load_config()
        config.server = normalize_server_url(url)
        save_config(config)
        typer.echo(f"Saved server {config.server} to {config_path()}")


@config_app.command("show")
def show_config() -> None:
    """Show saved settings."""
    with _user_errors():
        config = load_config()
        typer.echo(f"Config file: {config_path()}")
        typer.echo(f"Server:      {config.server or '(not set)'}")
        for url, token in config.tokens.items():
            state = (
                "expired"
                if token.is_expired()
                else f"expires {token.expires_at:%Y-%m-%d %H:%M %Z}"
            )
            typer.echo(f"Signed in:   {url} ({token.scope}; {state})")
        saved_count = len(load_requests().requests)
        typer.echo(
            f"Save requests: {'on' if config.save_requests else 'off'} ({saved_count} saved)"
        )


class Toggle(StrEnum):
    ON = "on"
    OFF = "off"


@config_app.command("save-requests")
def set_save_requests(
    state: Annotated[Toggle, typer.Argument(help="Save new receive requests on this machine.")],
    delete: Annotated[
        bool | None,
        typer.Option(
            "--delete/--keep",
            help="When turning off, also delete saved requests. Default: ask.",
        ),
    ] = None,
) -> None:
    """Turn saving of receive requests (`psst requests`) on or off."""
    with _user_errors():
        config = load_config()
        config.save_requests = state is Toggle.ON
        save_config(config)
        if config.save_requests:
            typer.echo(f"Saving receive requests to {requests_path()}.", err=True)
            typer.echo(
                "View links contain the private key unless the request has a password; "
                "anyone who can read this file can reveal those requests.",
                err=True,
            )
            return
        count = len(load_requests().requests)
        if count and delete is None:
            delete = typer.confirm(
                f"Delete the {count} saved request(s)?", default=False
            )
        if delete:
            delete_requests()
            typer.echo("Saving turned off; saved requests deleted.", err=True)
        else:
            typer.echo("Saving turned off; existing saved requests kept.", err=True)


def _live_status(entry: SavedRequest) -> str:
    if entry.is_expired():
        return "expired"
    link = parse_view_link(entry.view_link)
    try:
        return operations.request_status(link, client=_client(link.server)).status
    except PsstError:
        return "unknown"


@requests_app.command("list")
def requests_list(
    offline: Annotated[
        bool, typer.Option("--offline", help="Don't ask the server for the status.")
    ] = False,
) -> None:
    """List saved receive requests and whether they have been submitted."""
    with _user_errors():
        store = load_requests()
        if not store.requests:
            typer.echo("No saved requests.", err=True)
            return
        typer.echo(f"{'ID':<9} {'STATUS':<10} {'EXPIRES (UTC)':<17} LABEL")
        for entry in sorted(store.requests, key=lambda r: r.created_at):
            state = (
                ("expired" if entry.is_expired() else "-")
                if offline
                else _live_status(entry)
            )
            expires = entry.expires_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M")
            typer.echo(f"{entry.short_id:<9} {state:<10} {expires:<17} {entry.label}")


@requests_app.command("show")
def requests_show(
    ref: Annotated[
        str, typer.Argument(help="Label or id (prefix) of the saved request.")
    ],
    view_link: Annotated[
        bool, typer.Option("--view-link", help="Also print the private view link.")
    ] = False,
) -> None:
    """Print a saved request's submit link (and optionally its view link)."""
    with _user_errors():
        entry = load_requests().find(ref)
        typer.echo(f"Submit link (share this): {entry.submit_link}")
        if view_link:
            typer.echo(f"View link (keep private): {entry.view_link}")
        typer.echo(f"Expires at: {entry.expires_at:%Y-%m-%d %H:%M %Z}", err=True)


@requests_app.command("reveal")
def requests_reveal(
    ref: Annotated[
        str, typer.Argument(help="Label or id (prefix) of the saved request.")
    ],
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir", "-o", file_okay=False, help="Where to save revealed files."
        ),
    ] = Path("."),
) -> None:
    """Reveal a saved request's submission."""
    with _user_errors():
        _reveal_link(parse_view_link(load_requests().find(ref).view_link), output_dir)


@requests_app.command("label")
def requests_label(
    ref: Annotated[
        str, typer.Argument(help="Label or id (prefix) of the saved request.")
    ],
    label: Annotated[str, typer.Argument(help="New label; empty to clear.")],
) -> None:
    """Change a saved request's label."""
    with _user_errors():
        store = load_requests()
        store.find(ref).label = label
        save_requests(store)


@requests_app.command("remove")
def requests_remove(
    ref: Annotated[
        str, typer.Argument(help="Label or id (prefix) of the saved request.")
    ],
) -> None:
    """Forget a saved request (it stays on the server until it expires)."""
    with _user_errors():
        store = load_requests()
        entry = store.find(ref)
        store.remove(entry)
        save_requests(store)
        typer.echo(f"Removed {entry.short_id}.", err=True)


@requests_app.command("prune")
def requests_prune() -> None:
    """Forget saved requests that expired or are gone from the server."""
    with _user_errors():
        store = load_requests()
        stale = [
            entry
            for entry in store.requests
            if _live_status(entry) in ("expired", "gone")
        ]
        for entry in stale:
            store.remove(entry)
        save_requests(store)
        typer.echo(f"Removed {len(stale)} saved request(s).", err=True)


@requests_app.command("clear")
def requests_clear(
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Don't ask for confirmation.")
    ] = False,
) -> None:
    """Delete all saved requests."""
    with _user_errors():
        if yes or typer.confirm("Delete all saved requests?", default=False):
            delete_requests()
            typer.echo("All saved requests deleted.", err=True)


def main() -> None:
    app()
