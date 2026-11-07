"""Saved receive requests through the CLI against a live server."""

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from psst_cli.cli import app
from psst_cli.saved import load_requests

SERVER = os.environ.get("PSST_TEST_SERVER")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not SERVER, reason="PSST_TEST_SERVER is not set"),
]


@pytest.fixture(autouse=True)
def isolated_app_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("PSST_SERVER", SERVER or "")


def _status(runner: CliRunner, label: str) -> str:
    result = runner.invoke(app, ["requests", "list"])
    assert result.exit_code == 0, result.output
    line = next(line for line in result.stdout.splitlines() if line.endswith(label))
    return line.split()[1]


def test_saved_request_lifecycle() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["request", "--no-save"])
    assert result.exit_code == 0, result.output
    assert not load_requests().requests

    assert runner.invoke(app, ["config", "save-requests", "on"]).exit_code == 0
    result = runner.invoke(app, ["request", "--label", "deploy key"])
    assert result.exit_code == 0, result.output
    assert _status(runner, "deploy key") == "pending"

    submit_link = load_requests().find("deploy key").submit_link
    result = runner.invoke(app, ["submit", submit_link], input="from a colleague\n")
    assert result.exit_code == 0, result.output
    assert _status(runner, "deploy key") == "submitted"

    result = runner.invoke(app, ["requests", "reveal", "deploy key"])
    assert result.exit_code == 0, result.output
    assert "from a colleague" in result.stdout
    assert _status(runner, "deploy key") == "gone"

    assert runner.invoke(app, ["requests", "prune"]).exit_code == 0
    assert not load_requests().requests
