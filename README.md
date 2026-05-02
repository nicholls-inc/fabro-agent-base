# fabro-agent-base

Reusable Docker base image for [fabro](https://docs.fabro.sh) coding-agent workflows. Provides a GitHub-App authentication surface (lazy-mint installation tokens, PATH-shadow `gh` wrapper, git credential helper) plus a fail-closed `auth-smoke` gate that consuming workflows invoke before any LLM cost. Distributed via `ghcr.io/nicholls-inc/fabro-agent-base:<semver>`; consumers `FROM` this image and add their own per-workflow tooling on top.

## What's in the image

All five binaries live at `/usr/local/bin/` and are chmod 0755.

- `gh-mint-token` ([source](docker/gh-mint-token.py)) — Python script that mints a GitHub App installation token, caches it at `/run/gh-token` and the installation's permission set at `/run/gh-permissions.json`, refreshes when within 5 minutes of expiry. Self-test mode validates argument parsing without secrets.
- `gh` ([source](docker/gh-wrapper.sh)) — PATH-shadow wrapper for the apt-installed GitHub CLI at `/usr/bin/gh`. On every invocation it lazy-mints/refreshes the token via `gh-mint-token`, exports `GH_TOKEN`, then `exec`s the real `gh`.
- `git-credential-github-app` ([source](docker/git-credential-github-app.sh)) — git credential helper registered globally in `/etc/gitconfig` for `https://github.com`. Hands out the same minted token to git over HTTPS so `git push`, `git fetch`, and `git clone` all work without a separate auth step.
- `entrypoint.sh` ([source](docker/entrypoint.sh)) — pre-warms the token cache so the first `gh` invocation in the container doesn't pay the ~200 ms mint latency, then exec's the container's command.
- `auth-smoke` ([source](docker/auth-smoke.sh)) — fail-closed gate consuming workflows invoke before any LLM cost. Accepts repeatable `--require-permission KEY=VAL` flags to assert minimum installation permissions, an optional `--workspace PATH` to assert the workspace exists and is a git repo, and `--self-test` to validate argument parsing. Prints exactly `AUTH_OK` to stdout on success.

## Required env vars at runtime

The inter-image contract requires four environment variables. The first three are mandatory; `ANTHROPIC_API_KEY` is optional but checked by `auth-smoke` when consuming workflows use Claude.

| Variable | Format | Purpose |
|---|---|---|
| `GITHUB_APP_ID` | numeric | The App's ID |
| `GITHUB_APP_INSTALLATION_ID` | numeric | The installation on the consuming repo's org |
| `GITHUB_APP_PRIVATE_KEY` | PEM | The App's private key |
| `ANTHROPIC_API_KEY` | string (optional) | Required if the consuming workflow uses Claude |

> **Important:** all four must be exported in the **fabro daemon's environment**, not just the operator's shell — fabro spawns the container as a child of its daemon, and unexported vars don't propagate. Restart the daemon after adding new exports; running `fabro server` already-running won't pick them up. (See the `project_fabro_env_interpolation` lesson: wrong env wiring frequently surfaces as a misleading downstream `PyJWT "Could not parse the provided public key"`.)

## Inter-image contracts (frozen once shipped — never break)

These surfaces are part of the image's public API. Once a version is published to ghcr.io, the contract is frozen for that version line — changes to any of the items below are major-version breaks.

- **Success token:** `auth-smoke` prints exactly `AUTH_OK` to stdout on success.
- **Wrapper paths:** `/usr/local/bin/gh`, `/usr/local/bin/auth-smoke`, `/usr/local/bin/gh-mint-token`.
- **Cache paths:** `/run/gh-token` (token), `/run/gh-permissions.json` (installation permission set).
- **Required env-var names:** `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, `GITHUB_APP_PRIVATE_KEY`, optional `ANTHROPIC_API_KEY`.
- **Flag shape on `auth-smoke`:** `--require-permission KEY=VAL` (repeatable), `--workspace PATH`, `--self-test`.
- **Flag shape on `gh-mint-token`:** `--require-permission KEY=VAL` (repeatable), `--self-test`.

## How consumers use it

Downstream workflow image:

```dockerfile
FROM ghcr.io/nicholls-inc/fabro-agent-base:0.1.0

# Per-workflow tooling goes here.
RUN apt-get update && apt-get install -y --no-install-recommends ripgrep \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir uv \
    && uv pip install --system --no-cache -r /tmp/requirements.txt
```

Per-workflow `auth-smoke.sh` thin wrapper (the consumer pins its own permission requirements):

```bash
#!/usr/bin/env bash
exec /usr/local/bin/auth-smoke --require-permission contents=write
```

> **Local tagging note:** tag the consumer image as `fabro-agent:latest` locally — fabro's docker provider hardcodes that name, and `image =` keys in `workflow.toml` are silently accepted but ignored (see the `fabro-workflow-author` skill landmine catalog).

## Versioning policy

[Semantic versioning](https://semver.org/). `:latest` is a moving alias; **consumers MUST pin to a specific version tag** (e.g. `:0.1.0`) so a future major bump can't break their workflow without warning.

- **Patch** (`0.1.0` → `0.1.1`) — behaviour-preserving fix.
- **Minor** (`0.1.0` → `0.2.0`) — additive feature; existing contract unchanged.
- **Major** (`0.x` → `1.0`, `1.x` → `2.0`) — contract break (any item under "Inter-image contracts").

`v0.x` is experimental until the second consumer onboards; until then the contract may move with minor bumps to absorb early lessons.

## Local development

Build the base image locally:

```
docker build -t fabro-agent-base:dev .
```

Run the bats test suite (lives in `tests/`):

```
./tests/run-tests.sh
```

## CI

GitHub Actions builds and tests the image on every PR. On a `VERSION` bump landing on `master`, the same workflow also pushes `ghcr.io/nicholls-inc/fabro-agent-base:<VERSION>` and `:latest`. The CI workflow lives at `.github/workflows/build-and-test.yml`.

## Source

<https://github.com/nicholls-inc/fabro-agent-base>
