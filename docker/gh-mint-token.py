#!/usr/bin/env python3
"""Mint, cache, and refresh a GitHub App installation token.

Modes:
  --self-test                Sign a JWT against an ephemeral RSA key and
                             exercise the cache write/read path without
                             making any real GitHub API call. Used by the
                             Dockerfile build-time smoke test to fail-fast
                             on wrapper regressions.
  --mint                     Force a real mint, ignoring any existing
                             cache. Writes the token to /run/gh-token and
                             the App's permissions map to
                             /run/gh-permissions.json (both mode 0600) and
                             prints the token.
  --permissions              Print the cached permissions JSON. Mints if
                             the cache is missing or stale.
  --require-permission K=V   Exit 0 if the App's permissions map contains
                             K=V (e.g. `contents=write`); exit 1 with a
                             clear error otherwise. Used by auth-smoke.sh
                             to fail-closed before any LLM cost when the
                             App lacks the access the workflow needs.
  (default)                  Read /run/gh-token. If missing or older than
                             the refresh threshold (55 min), re-mint.
                             Print the token.

The wrapper scripts (gh-wrapper.sh, git-credential-github-app.sh) call this
in default mode every invocation. The cost of a cache hit is one stat() and
one read(); the cost of a miss is ~200 ms (one HTTPS round trip).

Required env (real-mint and default modes — NOT --self-test):
  GITHUB_APP_PRIVATE_KEY        PEM-encoded RSA private key
  GITHUB_APP_ID                 Numeric GitHub App ID (issuer of the JWT)
  GITHUB_APP_INSTALLATION_ID    Numeric installation id for the target
                                repo/org

Contract: GITHUB_APP_ID and GITHUB_APP_INSTALLATION_ID are read from the
environment, validated against `^[0-9]+$`, and only then interpolated into
the access-tokens URL. Validation is fail-closed: missing or non-numeric
values exit non-zero with a message naming the offending variable, before
any network I/O. The dynamic URL segment is therefore digits-only from a
static-analysis standpoint and remains effectively a literal for SSRF
purposes — do not relax the regex without re-evaluating the threat model.
Self-test runs entirely offline and does NOT require these env vars.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

import jwt
import requests

CACHE_PATH = Path("/run/gh-token")
PERMISSIONS_PATH = Path("/run/gh-permissions.json")
REFRESH_AFTER_SECONDS = 55 * 60  # token is valid 60m; mint a fresh one with 5m margin

_NUMERIC_RE = re.compile(r"^[0-9]+$")


def _require_numeric_env(name: str) -> str:
    """Read an env var and require it to be a non-empty numeric string.

    Fail-closed: exits non-zero with a message naming the variable on
    missing/empty or malformed values. The numeric constraint is what makes
    interpolating the value into the access-tokens URL safe from SSRF —
    callers downstream rely on this validation and must not relax it.
    """
    value = os.environ.get(name, "")
    if not value:
        print(
            f"ERROR: {name} is not set or empty — required to mint GitHub App tokens",
            file=sys.stderr,
        )
        sys.exit(1)
    if not _NUMERIC_RE.match(value):
        print(
            f"ERROR: {name} must be numeric (matching ^[0-9]+$) — got a non-numeric value",
            file=sys.stderr,
        )
        sys.exit(1)
    return value


def _sign_jwt(app_id: str, private_key: str) -> str:
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


def _mint_real_token() -> tuple[str, dict]:
    """Mint a fresh installation token from GitHub.

    Returns (token, permissions). `permissions` is the access-token
    response's `permissions` field — a map of permission name to access
    level (e.g. {"contents": "write", "pull_requests": "write"}). Used by
    the `--require-permission` mode to fail-closed before LLM cost when
    the App lacks an access the workflow needs.
    """
    private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")
    if not private_key:
        print(
            "ERROR: GITHUB_APP_PRIVATE_KEY is not set or empty — required to mint GitHub App tokens",
            file=sys.stderr,
        )
        sys.exit(1)

    app_id = _require_numeric_env("GITHUB_APP_ID")
    installation_id = _require_numeric_env("GITHUB_APP_INSTALLATION_ID")

    try:
        app_jwt = _sign_jwt(app_id, private_key)
    except Exception as e:
        print(
            f"ERROR: JWT signing failed ({type(e).__name__}: {e}) — check key format (PEM RSA)",
            file=sys.stderr,
        )
        sys.exit(1)

    # GITHUB_APP_INSTALLATION_ID is validated as ^[0-9]+$ above before this
    # f-string runs; the URL therefore contains only digits in the dynamic
    # segment and remains effectively a literal from a static-analysis
    # standpoint. Do not relax the validation without re-evaluating SSRF risk.
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    try:
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )
    except requests.RequestException as e:
        print(f"ERROR: network failure reaching GitHub API: {e}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code >= 400:
        # Only emit the GitHub-side `message` field. resp.text is dumped by
        # other endpoints in the wild as a token-bearing response on partial-
        # success or redirect, and fabro captures stage stderr into PR-visible
        # transcripts — so a literal `resp.text` print is a token-leak
        # waiting to happen.
        try:
            err_msg = resp.json().get("message", "<no message field>")
        except ValueError:
            err_msg = "<non-JSON error body>"
        print(f"ERROR: GitHub API HTTP {resp.status_code}: {err_msg}", file=sys.stderr)
        sys.exit(1)

    try:
        data = resp.json()
    except ValueError as e:
        print(f"ERROR: GitHub API returned non-JSON response: {e}", file=sys.stderr)
        sys.exit(1)

    token = data.get("token")
    if not token or not token.startswith("ghs_"):
        # Don't emit `data` — a malformed-but-token-bearing response (e.g.
        # the prefix changes) would leak the token into stderr.
        print(
            f"ERROR: GitHub API response missing valid 'token' (keys: {sorted(data.keys())})",
            file=sys.stderr,
        )
        sys.exit(1)
    permissions = data.get("permissions") or {}
    if not isinstance(permissions, dict):
        print(
            f"ERROR: GitHub API response 'permissions' is not an object (got {type(permissions).__name__})",
            file=sys.stderr,
        )
        sys.exit(1)
    return token, permissions


def _write_owner_only(path: Path, payload: bytes) -> None:
    # umask 077 equivalent: write owner-readable only.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def _write_cache(token: str, permissions: dict) -> None:
    _write_owner_only(CACHE_PATH, token.encode())
    _write_owner_only(PERMISSIONS_PATH, json.dumps(permissions).encode())


def _cache_is_fresh() -> bool:
    if not CACHE_PATH.exists():
        return False
    age = time.time() - CACHE_PATH.stat().st_mtime
    return age < REFRESH_AFTER_SECONDS


def _read_cache() -> str:
    return CACHE_PATH.read_text().strip()


def _read_permissions_cache() -> dict:
    """Return cached permissions, minting a fresh token if the cache is
    missing or stale. The token cache and permissions cache are written
    atomically together by `_write_cache`, so we key freshness off the
    token cache to keep them consistent.
    """
    if _cache_is_fresh() and PERMISSIONS_PATH.exists():
        try:
            return json.loads(PERMISSIONS_PATH.read_text())
        except (OSError, ValueError):
            pass  # fall through to remint
    token, permissions = _mint_real_token()
    _write_cache(token, permissions)
    return permissions


def _mode_default() -> None:
    if _cache_is_fresh():
        try:
            cached = _read_cache()
        except OSError:
            cached = ""
        # Re-validate the prefix on read — a corrupted cache (partial write,
        # foreign-process clobber, leftover self-test sentinel) would
        # otherwise be served as a real token.
        if cached.startswith("ghs_"):
            sys.stdout.write(cached)
            return
    token, permissions = _mint_real_token()
    _write_cache(token, permissions)
    sys.stdout.write(token)


def _mode_mint() -> None:
    token, permissions = _mint_real_token()
    _write_cache(token, permissions)
    sys.stdout.write(token)


def _mode_permissions() -> None:
    permissions = _read_permissions_cache()
    sys.stdout.write(json.dumps(permissions))


def _mode_require_permission(spec: str) -> None:
    """Fail-closed permission check.

    `spec` is `KEY=VALUE` (e.g. `contents=write`). Exits 0 if the App's
    permissions map contains exactly that pair; exits 1 otherwise with a
    clear error showing what was expected and what the App actually has.
    Used by auth-smoke.sh as a pre-LLM gate.
    """
    if "=" not in spec:
        print(
            f"ERROR: --require-permission expects KEY=VALUE (e.g. contents=write), got {spec!r}",
            file=sys.stderr,
        )
        sys.exit(2)
    key, _, expected = spec.partition("=")
    key = key.strip()
    expected = expected.strip()
    if not key or not expected:
        print(
            f"ERROR: --require-permission KEY and VALUE must be non-empty, got {spec!r}",
            file=sys.stderr,
        )
        sys.exit(2)

    permissions = _read_permissions_cache()
    actual = permissions.get(key)
    if actual != expected:
        # Surface the full permissions map on failure so the operator can
        # see what the App *does* have without re-running with --permissions.
        # This is safe to log: permission names/values are public metadata,
        # not credentials.
        print(
            f"ERROR: GitHub App is missing required permission {key}={expected!r} "
            f"(App has {key}={actual!r}). Full permissions: {permissions}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"✓ GitHub App permission {key}={actual}", file=sys.stderr)


def _mode_self_test() -> None:
    """Exercise the cache + JWT signing paths without hitting GitHub.

    Generates an ephemeral RSA key in-memory, signs a JWT against it, writes
    a sentinel cache file, reads it back, and removes it. Any exception fails
    the build.

    Self-test is fully offline and does NOT read GITHUB_APP_ID,
    GITHUB_APP_INSTALLATION_ID, or GITHUB_APP_PRIVATE_KEY. The Dockerfile
    build-time smoke test invokes this in a freshly built image with zero
    secrets present, so any env-var validation here would break the build.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        # PyJWT pulls in cryptography for RS256, so this should never miss.
        print(
            "ERROR: cryptography package missing — required for self-test (and PyJWT RS256)",
            file=sys.stderr,
        )
        sys.exit(1)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Hardcoded fake APP_ID — self-test never reads GITHUB_APP_ID from env so
    # the Dockerfile build smoke test passes with zero env vars set.
    signed = _sign_jwt("999999", pem)
    if not signed or not isinstance(signed, str):
        print("ERROR: self-test JWT signing produced no output", file=sys.stderr)
        sys.exit(1)

    # Round-trip the same O_CREAT|O_TRUNC|0600 write pattern as
    # _write_cache, but against a tempfile — never touch the real
    # /run/gh-token. A crashed self-test must not leave a sentinel that
    # the wrapper would later read back as a token.
    sentinel = "ghs_self_test_sentinel"
    tmp_dir = tempfile.mkdtemp(prefix="gh-mint-selftest-")
    tmp_path = Path(tmp_dir) / "token"
    try:
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, sentinel.encode())
        finally:
            os.close(fd)
        if tmp_path.read_text().strip() != sentinel:
            print("ERROR: self-test cache write/read round-trip failed", file=sys.stderr)
            sys.exit(1)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
            os.rmdir(tmp_dir)
        except OSError:
            pass
    print("✓ gh-mint-token self-test OK", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--self-test", action="store_true", help="exercise JWT + cache paths offline"
    )
    parser.add_argument("--mint", action="store_true", help="force real mint, ignore cache")
    parser.add_argument(
        "--permissions",
        action="store_true",
        help="print the cached App permissions JSON (mints if cache is stale)",
    )
    parser.add_argument(
        "--require-permission",
        metavar="KEY=VALUE",
        help="exit 0 iff the App's permissions map contains KEY=VALUE (e.g. contents=write)",
    )
    args = parser.parse_args()

    if args.self_test:
        _mode_self_test()
    elif args.mint:
        _mode_mint()
    elif args.permissions:
        _mode_permissions()
    elif args.require_permission is not None:
        # Use `is not None` rather than truthiness: `--require-permission ""`
        # would otherwise fall through to _mode_default() and print a live
        # `ghs_` token to stdout. _mode_require_permission validates the
        # spec is non-empty inside, but only reaches that check if we
        # dispatch here. Same fail-open shape as LLM_QUALITY_REVIEW_FAIL_OPEN.
        _mode_require_permission(args.require_permission)
    else:
        _mode_default()


if __name__ == "__main__":
    main()
