"""Opt-in local store of receive requests, like the web app's saved requests."""

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from . import PsstError
from .config import app_dir, write_private


class SavedRequest(BaseModel):
    view_id: str
    label: str = ""
    submit_link: str
    # Holds the private key unless the request is password protected.
    view_link: str
    created_at: datetime
    expires_at: datetime

    @property
    def short_id(self) -> str:
        return self.view_id[:8]

    def is_expired(self, now: datetime | None = None) -> bool:
        return self.expires_at <= (now or datetime.now(UTC))


class SavedRequests(BaseModel):
    requests: list[SavedRequest] = []

    def add(self, request: SavedRequest) -> None:
        self.requests = [r for r in self.requests if r.view_id != request.view_id] + [
            request
        ]

    def find(self, ref: str) -> SavedRequest:
        """Look up by exact label or by a prefix of the view identifier."""
        ref = ref.strip()
        if not ref:
            raise PsstError("No saved request given")
        matches = [r for r in self.requests if r.label == ref]
        if not matches:
            matches = [r for r in self.requests if r.view_id.startswith(ref.lower())]
        if not matches:
            raise PsstError(f"No saved request matches {ref!r}")
        if len(matches) > 1:
            raise PsstError(f"{ref!r} matches several saved requests; use a longer id")
        return matches[0]

    def remove(self, request: SavedRequest) -> None:
        self.requests = [r for r in self.requests if r.view_id != request.view_id]


def requests_path() -> Path:
    return app_dir() / "requests.json"


def load_requests(path: Path | None = None) -> SavedRequests:
    path = path or requests_path()
    if not path.exists():
        return SavedRequests()
    try:
        return SavedRequests.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        raise PsstError(f"Invalid saved requests file: {path}") from exc


def save_requests(store: SavedRequests, path: Path | None = None) -> None:
    write_private(path or requests_path(), store.model_dump_json(indent=2) + "\n")


def delete_requests(path: Path | None = None) -> None:
    (path or requests_path()).unlink(missing_ok=True)
