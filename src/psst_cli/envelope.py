"""Plaintext envelope: what gets encrypted."""

import mimetypes
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, TypeAdapter, ValidationError

from .crypto import b64decode, b64encode


class TextEnvelope(BaseModel):
    type: Literal["text"] = "text"
    content: str
    format: str | None = None


class FileEntry(BaseModel):
    filename: str
    mimetype: str = "application/octet-stream"
    data: str


class FilesEnvelope(BaseModel):
    type: Literal["files"] = "files"
    files: list[FileEntry]


class LegacyFileEnvelope(FileEntry):
    type: Literal["file"] = "file"


Envelope = Annotated[
    TextEnvelope | FilesEnvelope | LegacyFileEnvelope, Field(discriminator="type")
]
_envelope_adapter = TypeAdapter(Envelope)


def text_envelope(content: str, markdown: bool = False) -> bytes:
    envelope = TextEnvelope(content=content, format="markdown" if markdown else None)
    return envelope.model_dump_json(exclude_none=True).encode("utf-8")


def files_envelope(paths: list[Path]) -> bytes:
    files = [
        FileEntry(
            filename=path.name,
            mimetype=mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            data=b64encode(path.read_bytes()),
        )
        for path in paths
    ]
    return FilesEnvelope(files=files).model_dump_json().encode("utf-8")


class RevealedFile(BaseModel):
    filename: str
    mimetype: str
    data: bytes


class Revealed(BaseModel):
    text: str | None = None
    format: str | None = None
    files: list[RevealedFile] = []


def parse_envelope(plaintext: bytes) -> Revealed:
    """Decode a decrypted payload; anything that is not a known envelope is shown as text."""
    text = plaintext.decode("utf-8", errors="replace")
    try:
        envelope = _envelope_adapter.validate_json(plaintext)
    except ValidationError:
        return Revealed(text=text)
    match envelope:
        case TextEnvelope():
            return Revealed(text=envelope.content, format=envelope.format)
        case FilesEnvelope():
            entries = envelope.files
        case LegacyFileEnvelope():
            entries = [envelope]
    return Revealed(
        files=[
            RevealedFile(
                filename=safe_filename(e.filename),
                mimetype=e.mimetype,
                data=b64decode(e.data),
            )
            for e in entries
        ]
    )


def safe_filename(name: str) -> str:
    cleaned = name.replace("/", "").replace("\\", "").replace("\0", "").strip()
    if cleaned in ("", ".", ".."):
        return "whisper-file"
    return cleaned
