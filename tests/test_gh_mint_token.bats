#!/usr/bin/env bats
# Regression suite for /usr/local/bin/gh-mint-token.
#
# Each test asserts a fail-closed behavior locked in by recent hardening
# work. Test names follow `regression-<PR>-<description>` so the originating
# PR is grep-discoverable from the test output.
#
# Critical defense-in-depth shape: every test on a token-leak path asserts
# BOTH `[ "$status" -ne 0 ]` AND `[[ "$output" != *"ghs_"* ]]`. PR #1605's
# bug shape was exactly "non-zero exit AFTER printing a token to stdout" —
# the status check alone would not have caught it.
#
# Out of scope: real-mint paths require valid GitHub App credentials and
# network access to api.github.com; those live in manual side-by-side
# verification. Bats covers fail-closed and offline self-test only.

setup() {
    # Default to a clean env. Each test sets only what it needs.
    unset GITHUB_APP_ID GITHUB_APP_INSTALLATION_ID GITHUB_APP_PRIVATE_KEY
}

# ----------------------------------------------------------------------------
# --self-test: load-bearing positive case (Dockerfile build smoke).
# Self-test must NOT read GITHUB_APP_ID / INSTALLATION_ID / PRIVATE_KEY —
# the Dockerfile RUN layer invokes it with zero secrets present. Adding
# env-var validation to the self-test path would break the build.
# ----------------------------------------------------------------------------

@test "regression-baseline: --self-test exits 0 with no env vars set" {
    run /usr/local/bin/gh-mint-token --self-test
    [ "$status" -eq 0 ]
    [[ "$output" == *"gh-mint-token self-test OK"* ]]
}

@test "regression-baseline: --self-test does not write a sentinel to /run/gh-token" {
    # A crashed self-test must not leave a sentinel at /run/gh-token that
    # the wrapper would later read back as a real token. Verify the file
    # does not exist after a clean self-test run.
    rm -f /run/gh-token
    run /usr/local/bin/gh-mint-token --self-test
    [ "$status" -eq 0 ]
    [ ! -f /run/gh-token ]
}

@test "regression-baseline: --help exits 0 and prints usage" {
    run /usr/local/bin/gh-mint-token --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"--self-test"* ]]
    [[ "$output" == *"--require-permission"* ]]
}

# ----------------------------------------------------------------------------
# PR #1605: --require-permission empty value MUST exit non-zero AND NOT
# print a `ghs_` token. The Python `is not None` (rather than truthy) check
# is the canonical defense — `--require-permission ""` would otherwise fall
# through to _mode_default() and print a live token to stdout.
# ----------------------------------------------------------------------------

@test "regression-1605: --require-permission \"\" rejects empty value, no token leak" {
    run /usr/local/bin/gh-mint-token --require-permission ""
    [ "$status" -ne 0 ]
    # CRITICAL: empty value must NOT fall through to _mode_default() and
    # print a `ghs_` token. This is the bug PR #1605 closed.
    [[ "$output" != *"ghs_"* ]]
    # Empty string has no '=' so hits the "expects KEY=VALUE" branch first.
    # Assert any of the load-bearing error tokens — KEY=VALUE format error
    # OR the empty-value error from the second-stage check.
    [[ "$output" == *"KEY=VALUE"* || "$output" == *"non-empty"* || "$output" == *"empty"* ]]
}

@test "regression-1605: --require-permission= (= form, empty) rejects empty value" {
    run /usr/local/bin/gh-mint-token --require-permission=
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    # `--require-permission=` parses to value "" (no '=' in the value), so
    # hits the same "expects KEY=VALUE" branch as the bare empty-string case.
    [[ "$output" == *"KEY=VALUE"* || "$output" == *"non-empty"* || "$output" == *"empty"* ]]
}

@test "regression-1605: --require-permission contents (no =) rejects malformed value" {
    run /usr/local/bin/gh-mint-token --require-permission contents
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"KEY=VALUE"* ]]
}

@test "regression-1605: --require-permission =write (empty key) rejects malformed value" {
    run /usr/local/bin/gh-mint-token --require-permission =write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"non-empty"* || "$output" == *"empty"* ]]
}

@test "regression-1605: --require-permission contents= (empty value) rejects malformed value" {
    run /usr/local/bin/gh-mint-token --require-permission contents=
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"non-empty"* || "$output" == *"empty"* ]]
}

# ----------------------------------------------------------------------------
# Numeric-validation contract for GITHUB_APP_ID / GITHUB_APP_INSTALLATION_ID.
# These IDs are interpolated into the access-tokens URL; the `^[0-9]+$`
# regex is what makes that interpolation effectively SSRF-safe. Validation
# is fail-closed: missing or non-numeric values exit non-zero with a message
# naming the offending variable, before any network I/O.
#
# NOTE: --require-permission goes through _read_permissions_cache(), which
# only mints if the cache is missing/stale. Tests below first ensure the
# cache files don't exist so the validation path is exercised every run.
# ----------------------------------------------------------------------------

clear_cache() {
    rm -f /run/gh-token /run/gh-permissions.json
}

@test "new-envvars: --require-permission with GITHUB_APP_ID unset → named-var error" {
    clear_cache
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "new-envvars: --require-permission with GITHUB_APP_ID empty → named-var error" {
    clear_cache
    export GITHUB_APP_ID=""
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "new-envvars: --require-permission with GITHUB_APP_ID=foo (non-numeric) → \"numeric\" error" {
    clear_cache
    export GITHUB_APP_ID="foo"
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"numeric"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "new-envvars: --require-permission with GITHUB_APP_ID=12abc (mixed) → \"numeric\" error" {
    clear_cache
    export GITHUB_APP_ID="12abc"
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"numeric"* ]]
}

@test "new-envvars: --require-permission with GITHUB_APP_INSTALLATION_ID unset → named-var error" {
    clear_cache
    export GITHUB_APP_ID="3457355"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

@test "new-envvars: --require-permission with GITHUB_APP_INSTALLATION_ID empty → named-var error" {
    clear_cache
    export GITHUB_APP_ID="3457355"
    export GITHUB_APP_INSTALLATION_ID=""
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

@test "new-envvars: --require-permission with GITHUB_APP_INSTALLATION_ID=foo (non-numeric) → \"numeric\" error" {
    clear_cache
    export GITHUB_APP_ID="3457355"
    export GITHUB_APP_INSTALLATION_ID="foo"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"numeric"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

# ----------------------------------------------------------------------------
# Default mode (no flags) — same numeric/missing validation must apply.
# Default mode reads through _mode_default → _mint_real_token, which calls
# _require_numeric_env for both IDs.
# ----------------------------------------------------------------------------

@test "new-envvars: default mode with GITHUB_APP_ID unset → named-var error" {
    clear_cache
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "new-envvars: default mode with GITHUB_APP_ID=foo → \"numeric\" error" {
    clear_cache
    export GITHUB_APP_ID="foo"
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"numeric"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "new-envvars: default mode with GITHUB_APP_INSTALLATION_ID unset → named-var error" {
    clear_cache
    export GITHUB_APP_ID="3457355"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

@test "new-envvars: default mode with GITHUB_APP_INSTALLATION_ID=foo → \"numeric\" error" {
    clear_cache
    export GITHUB_APP_ID="3457355"
    export GITHUB_APP_INSTALLATION_ID="foo"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"numeric"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

@test "new-envvars: default mode with GITHUB_APP_PRIVATE_KEY unset → named-var error" {
    clear_cache
    export GITHUB_APP_ID="3457355"
    export GITHUB_APP_INSTALLATION_ID="126181625"
    run /usr/local/bin/gh-mint-token
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_PRIVATE_KEY"* ]]
}

# ----------------------------------------------------------------------------
# --mint mode — same env-var contract as default. Locks in that --mint
# can't bypass the validation by some accidental alternative code path.
# ----------------------------------------------------------------------------

@test "new-envvars: --mint with GITHUB_APP_ID=foo → \"numeric\" error" {
    clear_cache
    export GITHUB_APP_ID="foo"
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----"
    run /usr/local/bin/gh-mint-token --mint
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"numeric"* ]]
}

# ----------------------------------------------------------------------------
# Cache corruption defense — _mode_default re-validates the `ghs_` prefix
# on read so a corrupted cache (partial write, foreign-process clobber,
# leftover self-test sentinel) is not served as a real token. We can't
# easily trigger a stale-but-fresh cache here without time-travel, but we
# can confirm a non-prefixed cache is rejected.
# ----------------------------------------------------------------------------

@test "regression-cache: corrupted cache (no ghs_ prefix) is not served as token" {
    # Write a fake-but-fresh cache with a non-token sentinel; default mode
    # should detect the missing prefix and try to re-mint (which fails on
    # our missing env). The script must NOT print the corrupted contents.
    echo "not_a_real_token" > /run/gh-token
    chmod 0600 /run/gh-token
    # Don't set the App credentials → mint fails → script must exit non-zero.
    run /usr/local/bin/gh-mint-token
    rm -f /run/gh-token
    [ "$status" -ne 0 ]
    [[ "$output" != *"not_a_real_token"* ]]
    [[ "$output" != *"ghs_"* ]]
}
