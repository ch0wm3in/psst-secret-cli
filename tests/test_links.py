import pytest

from psst_cli import PsstError
from psst_cli.envelope import parse_envelope, safe_filename
from psst_cli.links import UnsupportedVersionError, parse_submit_link, parse_view_link

URL = "https://psst.example/whisper/0b7c3c3e-8f4a-4a52-9a43-1f2d3e4f5a6b"
KEY = "wDBqzMt8+lAOxVIeB5bL6FLBKEl+Tj4KFY01ZOeZVb4="
TOKEN = "ea08e29fe009bce1f1f759c1fd37f071802e8fff28d201e9180709e53c8afda8"


def test_view_link_v1() -> None:
    link = parse_view_link(
        f"{URL}#v=1&reveal={TOKEN}&key=wDBqzMt8%2BlAOxVIeB5bL6FLBKEl%2BTj4KFY01ZOeZVb4%3D&extra=1"
    )
    assert link.server == "https://psst.example"
    assert link.view_id == "0b7c3c3e-8f4a-4a52-9a43-1f2d3e4f5a6b"
    assert link.version == 1
    assert link.reveal_token == TOKEN
    assert link.key is not None and len(link.key) == 32


def test_view_link_legacy_forms() -> None:
    with_token = parse_view_link(
        f"{URL}#reveal={TOKEN}&key=wDBqzMt8%2BlAOxVIeB5bL6FLBKEl%2BTj4KFY01ZOeZVb4%3D"
    )
    assert with_token.version == 0 and with_token.reveal_token == TOKEN
    bare = parse_view_link(f"{URL}#{KEY}")
    assert (
        bare.version == 0 and bare.reveal_token is None and bare.key == with_token.key
    )


def test_rejects_unknown_version() -> None:
    with pytest.raises(UnsupportedVersionError):
        parse_view_link(f"{URL}#v=2&reveal={TOKEN}")


def test_rejects_link_without_fragment() -> None:
    with pytest.raises(PsstError):
        parse_view_link(URL)


def test_submit_link_forms() -> None:
    fp = "2m5IHp0nSoIVbNDlEvuWusEChnthuEK4NlDv1CIjOP4="
    v1 = parse_submit_link(
        f"{URL}#v=1&fp=2m5IHp0nSoIVbNDlEvuWusEChnthuEK4NlDv1CIjOP4%3D"
    )
    legacy = parse_submit_link(f"{URL}#{fp}")
    assert v1.fingerprint == legacy.fingerprint
    assert (v1.version, legacy.version) == (1, 0)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("../../etc/passwd", "....etcpasswd"),
        ("a\\b\0c.txt", "abc.txt"),
        ("..", "whisper-file"),
        ("", "whisper-file"),
    ],
)
def test_safe_filename(name: str, expected: str) -> None:
    assert safe_filename(name) == expected


def test_legacy_file_and_unknown_plaintext() -> None:
    legacy = parse_envelope(
        b'{"type":"file","filename":"../x.txt","mimetype":"text/plain","data":"aGk="}'
    )
    assert legacy.files[0].filename == "..x.txt" and legacy.files[0].data == b"hi"
    assert parse_envelope(b"just text").text == "just text"
