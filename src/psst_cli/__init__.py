"""Command-line client for psst-secret."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("psst-secret-cli")
except PackageNotFoundError:
    __version__ = "unknown"

# psst-secret release whose docs/format.md and spec/vectors/ this client implements.
SPEC_VERSION = "v1.5.2"
API_VERSION = 1
FORMAT_VERSION = 1
# Versions this client can read; it only writes FORMAT_VERSION.
READABLE_FORMAT_VERSIONS = frozenset({0, 1})


class PsstError(Exception):
    """Base class for errors shown to the user."""
