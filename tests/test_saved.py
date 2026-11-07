import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from psst_cli import PsstError
from psst_cli.cli import app
from psst_cli.config import load_config
from psst_cli.saved import (
    SavedRequest,
    SavedRequests,
    load_requests,
    requests_path,
    save_requests,
)

NOW = datetime.now(UTC)


def _entry(
    view_id: str, label: str = "", expires_in: timedelta = timedelta(days=1)
) -> SavedRequest:
    return SavedRequest(
        view_id=view_id,
        label=label,
        submit_link=f"https://psst.example/submit/{view_id}#v=1&fp=x",
        view_link=f"https://psst.example/whisper/{view_id}#v=1&reveal={'a' * 64}&key=AAAA",
        created_at=NOW,
        expires_at=NOW + expires_in,
    )


@pytest.fixture(autouse=True)
def isolated_app_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("PSST_SERVER", raising=False)
    return tmp_path


def test_find_by_label_or_prefix() -> None:
    store = SavedRequests()
    store.add(_entry("aaaa1111-0000-0000-0000-000000000000", "db creds"))
    store.add(_entry("aaaa2222-0000-0000-0000-000000000000"))
    assert store.find("db creds").view_id.startswith("aaaa1111")
    assert store.find("AAAA2").view_id.startswith("aaaa2222")
    with pytest.raises(PsstError, match="several"):
        store.find("aaaa")
    with pytest.raises(PsstError, match="No saved request"):
        store.find("bbbb")


def test_store_is_private_and_roundtrips() -> None:
    store = SavedRequests()
    store.add(_entry("aaaa1111-0000-0000-0000-000000000000", "x"))
    save_requests(store)
    assert stat.S_IMODE(requests_path().stat().st_mode) == 0o600
    assert load_requests().requests[0].label == "x"


def test_enable_disable_and_offline_list() -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["config", "save-requests", "on"]).exit_code == 0
    assert load_config().save_requests

    store = SavedRequests()
    store.add(_entry("aaaa1111-0000-0000-0000-000000000000", "fresh"))
    store.add(
        _entry(
            "bbbb2222-0000-0000-0000-000000000000",
            "old",
            expires_in=timedelta(hours=-1),
        )
    )
    save_requests(store)
    result = runner.invoke(app, ["requests", "list", "--offline"])
    assert result.exit_code == 0
    assert "aaaa1111" in result.stdout and "fresh" in result.stdout
    assert "expired" in result.stdout

    result = runner.invoke(app, ["requests", "show", "fresh"])
    assert "Submit link" in result.stdout and "View link" not in result.stdout

    assert runner.invoke(app, ["requests", "label", "fresh", "renamed"]).exit_code == 0
    assert load_requests().find("renamed")
    assert runner.invoke(app, ["requests", "remove", "renamed"]).exit_code == 0
    assert len(load_requests().requests) == 1

    assert (
        runner.invoke(app, ["config", "save-requests", "off", "--delete"]).exit_code
        == 0
    )
    assert not load_config().save_requests
    assert not requests_path().exists()
