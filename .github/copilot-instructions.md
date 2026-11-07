# Copilot instructions for psst-secret-cli

`psst` is a command-line client for [psst-secret](https://github.com/ch0wm3in/psst-secret), a zero-knowledge secret-sharing app. Everything is encrypted and decrypted locally; the server only ever sees ciphertext.

## Spec and compatibility

- The client implements **format version 1** of psst-secret's `docs/format.md` and the `/api/v1/` API in `docs/api.md` and `spec/openapi.yaml`. The pinned release is `SPEC_VERSION` in `src/psst_cli/__init__.py`.
- When moving to a new psst-secret release, update all of these together:
  - `SPEC_VERSION`
  - the image tag in `tests/integration/docker-compose.yml` (image tags have no `v` prefix, e.g. `1.5.2`)
  - the README
  - the vectors in `tests/vectors/v1/`, re-copied from `spec/vectors/v1/` at that tag
- Read the spec at the pinned tag before changing crypto, links or API models. Don't guess field names.
- Follow the spec's compatibility policy:
  - Always write `v=1` in link fragments and `"v": 1` in requests that carry ciphertext.
  - Read versions 0 and 1 (`READABLE_FORMAT_VERSIONS`). A missing `v` means version 0.
  - Reject unknown versions before revealing, submitting or decrypting.
  - Ignore unknown JSON fields and fragment parameters.
- New server fields are optional in the pydantic models (default `None`), so older servers still work. `ApiInfo.features`, `policies` and `limits` are an example.

## Security rules (non-negotiable)

- Never send the URL fragment, keys, X-Wing seed, password or reveal token hash input to the server. Only `reveal_token` goes in the reveal body.
- Keep secrets out of shell history and logs:
  - Read secret text, view links and passwords from piped stdin or a hidden prompt (`typer.prompt(hide_input=True)`). Never take them as command-line arguments or options.
  - Submit links are allowed as arguments; they only contain a fingerprint.
  - Never print tokens, keys or codes in errors. Typer is configured with `pretty_exceptions_show_locals=False`, and the login callback handler suppresses access logging.
- Files that may hold secrets (`config.json` with API tokens, `requests.json` with saved view links) must be written with `config.write_private()` (mode `0600`, directory `0700`).
- API tokens are stored per normalized server URL and must only be sent to that server. HTTP requests use `allow_redirects=False`.
- Treat revealed filenames as untrusted: use `envelope.safe_filename()` and never overwrite existing files.
- Check that a server offers an option before using it (`operations.check_create_options`), and do it before prompting for secrets or encrypting.
- Avoid spending views: check status before revealing receive requests, and ask for the password before calling reveal.

## Architecture (`src/psst_cli/`)

| Module | Responsibility |
|---|---|
| `crypto.py` | AES-256-GCM, PBKDF2 (600k), HKDF (`psst-receive-v2`), base64, reveal tokens, fingerprints |
| `xwing.py` | X-Wing KEM (ML-KEM-768 + X25519) via `cryptography`; combiner label goes **last** |
| `links.py` | Building/parsing view and submit link fragments, including legacy v0 forms |
| `envelope.py` | Plaintext envelope (text/files/legacy file) as pydantic models |
| `api.py` | `requests`-based `Client` for `/api/v1/` plus pydantic request/response models |
| `operations.py` | High-level flows: send, create_request, submit, reveal, request_status, option checks |
| `auth.py` | API token sign-in: loopback redirect + PKCE (S256), optional manual code |
| `config.py` | Settings (`server`, `tokens`, `save_requests`) in the typer app dir |
| `saved.py` | Opt-in local store of receive requests |
| `cli.py` | Typer commands only; no crypto or HTTP details |

- Keep the CLI thin. Logic goes in `operations.py` and the lower modules, so tests can call it without the CLI.
- User-facing failures raise `PsstError` (or a subclass). The CLI turns them into `Error: ...` and exit code 1 through `_user_errors()`.
- Look up config paths at call time (`config_path()`, `requests_path()`), not at import. Tests isolate them with `XDG_CONFIG_HOME`.
- Settings belong under `psst config` (e.g. `psst config save-requests on|off`). `psst requests` only works with saved items.
- Status messages and hints go to stderr (`typer.echo(..., err=True)`). Stdout is for results such as links and revealed text, so output can be piped.

## Tooling

- Python **3.15** managed by **uv**.
- Dependencies: `typer`, `pydantic`, `requests`, `cryptography`. Don't add new ones unless the standard library and these can't do the job.
- `uv sync`, `uv run pytest`, `uv run psst ...`. Add packages with `uv add` / `uv add --dev`.
- Formatting and linting run through pre-commit: black, isort (black profile), flake8 (`setup.cfg`, 110 columns) and bandit.
- Build backend is `uv_build`. The package version is set from the release tag in CD (`uv version --frozen`), so leave `pyproject.toml`'s version alone.

## Testing

- `tests/test_vectors.py` runs the shared psst-secret test vectors. Any change to crypto, links or envelopes must keep them passing.
- Unit tests use fake clients or `typer.testing.CliRunner` and need no network.
- Integration tests (`-m integration`) need a live server:
  ```sh
  docker compose -f tests/integration/docker-compose.yml up -d
  PSST_TEST_SERVER=http://127.0.0.1:18000 uv run pytest -m integration
  ```
  The compose file raises rate limits and turns on the console email backend. Each container restart loses all data.
- Add or extend tests for every behavior change, including integration coverage for anything that talks to the server.

## CI/CD

- `.github/workflows/ci.yml` runs the unit and vector tests, plus integration tests against the published `ghcr.io/ch0wm3in/psst-secret` image. It is also reusable through `workflow_call`.
- `.github/workflows/cd.yml` runs on published releases: CI, then build, then publish to PyPI with trusted publishing (`id-token: write` only on the publish job, `pypi` environment).
- Pin every action to a full commit SHA with a `# vX.Y.Z` comment. Use `persist-credentials: false` on checkout, and pass untrusted values such as tag names through `env:`, never directly in `run:`.
