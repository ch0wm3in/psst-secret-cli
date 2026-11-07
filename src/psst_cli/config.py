"""Persistent CLI settings."""

import os
from datetime import UTC, datetime
from pathlib import Path

import typer
from pydantic import BaseModel, ValidationError

from . import PsstError


def app_dir() -> Path:
    return Path(typer.get_app_dir("psst"))


def config_path() -> Path:
    return app_dir() / "config.json"


def write_private(path: Path, text: str) -> None:
    """Write a file readable only by the current user."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


class StoredToken(BaseModel):
    access_token: str
    expires_at: datetime
    scope: str

    def is_expired(self) -> bool:
        return self.expires_at <= datetime.now(UTC)


class Config(BaseModel):
    server: str | None = None
    # API tokens keyed by normalized server URL, so a token is never sent to another server.
    tokens: dict[str, StoredToken] = {}
    # Opt-in: keep receive requests created by `psst request` in requests.json.
    save_requests: bool = False


def load_config(path: Path | None = None) -> Config:
    path = path or config_path()
    if not path.exists():
        return Config()
    try:
        return Config.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        raise PsstError(f"Invalid config file: {path}") from exc


def save_config(config: Config, path: Path | None = None) -> None:
    write_private(path or config_path(), config.model_dump_json(indent=2) + "\n")
