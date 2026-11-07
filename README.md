# psst-secret-cli

Command-line client for [psst-secret](https://github.com/ch0wm3in/psst-secret). Encryption happens locally; the link fragment, keys, and passwords are never sent to the server.

Implements format version 1 as specified in psst-secret `v1.5.2` (`docs/format.md`).

## Usage

```sh
psst config set-server https://psst.example.com   # or --server / PSST_SERVER
psst info                                          # compatibility check

# Send mode: secret text is read from stdin or a hidden prompt, never from arguments
psst send < secret.txt
psst send --file id_ed25519 --password --max-views 1 --expiry 1h

# Reveal: the link is read from stdin or a hidden prompt
psst reveal -o ./downloads

# Receive mode
psst request --password              # prints a submit link and a view link
psst request --notify-email me@example.com --reader alice@example.com
psst status                          # has the request been submitted? (view link from stdin/prompt)
psst submit '<submit link>' --file creds.env

# Saved receive requests (opt-in, kept in a private file on this machine)
psst config save-requests on         # or `psst request --save` for a single request
psst request --label "deploy key"
psst requests list                   # pending / submitted / gone, without using a view
psst requests reveal "deploy key"
psst requests prune                  # forget expired or revealed requests
psst config save-requests off        # offers to delete everything saved

# Sign in (servers that require it): browser sign-in with PKCE, token saved per server
psst login                      # --port 53682 --no-browser for SSH forwarding, --manual if enabled
psst logout                     # revokes the token
```

`PSST_TOKEN` overrides the saved token, e.g. in automation.

## Development

```sh
uv sync
uv run pytest                                      # unit tests and spec vectors

docker compose -f tests/integration/docker-compose.yml up -d
PSST_TEST_SERVER=http://127.0.0.1:18000 uv run pytest -m integration
```

The test vectors in `tests/vectors/v1/` are copied from `spec/vectors/v1/` at psst-secret `v1.5.2`.
