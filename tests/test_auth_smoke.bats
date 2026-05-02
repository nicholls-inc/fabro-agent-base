#!/usr/bin/env bats
# Regression suite for /usr/local/bin/auth-smoke.
#
# Each test asserts a fail-closed behavior locked in by a recent hardening
# PR (#1601, #1602, #1605, #1606) or by the parameterisation work for
# fabro-agent-base. Test names follow `regression-<PR>-<description>` so
# the originating PR is grep-discoverable from the test output.
#
# Critical defense-in-depth shape: every test on a token-leak path asserts
# BOTH `[ "$status" -ne 0 ]` AND `[[ "$output" != *"ghs_"* ]]`. The first
# alone is insufficient — a regression where the script exits non-zero AFTER
# printing a token to stdout would still be a leak. PR #1605 was exactly
# this shape.
#
# Out of scope: the success path (`AUTH_OK` printed) requires real GitHub
# API credentials and lives in the manual side-by-side verification step.
# Bats covers fail-closed only.

setup() {
    # Standard valid-looking env vars. Individual tests override one at a
    # time to exercise the corresponding failure mode. The private key is
    # syntactically PEM-shaped but not a real RSA key — gh auth status
    # would fail JWT signing on it. That's fine: every test in this file
    # is on a fail-closed path that exits BEFORE gh auth status runs, OR
    # accepts that JWT signing may be the rejection point (documented per
    # test).
    export ANTHROPIC_API_KEY="sk-ant-fake"
    export GITHUB_APP_ID="3457355"
    export GITHUB_APP_INSTALLATION_ID="126181625"
    export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
FAKEFAKEFAKE
-----END RSA PRIVATE KEY-----"

    # Per-test workspace with a valid github.com origin. Tests that
    # exercise the hostname regex override the origin URL.
    TEST_WORKSPACE="$(mktemp -d -t auth-smoke-test-XXXXXX)"
    git -C "$TEST_WORKSPACE" init -q
    git -C "$TEST_WORKSPACE" remote add origin "https://github.com/nicholls-inc/fabro-agent-base.git"
}

teardown() {
    if [[ -n "${TEST_WORKSPACE:-}" && -d "$TEST_WORKSPACE" ]]; then
        rm -rf "$TEST_WORKSPACE"
    fi
}

# ----------------------------------------------------------------------------
# --self-test mode: load-bearing positive case (Dockerfile build smoke)
# ----------------------------------------------------------------------------

@test "regression-baseline: --self-test exits 0 with no env vars set" {
    # The Dockerfile RUN layer invokes this with zero secrets present;
    # any env-var validation in the self-test path would fail the build.
    unset ANTHROPIC_API_KEY GITHUB_APP_ID GITHUB_APP_INSTALLATION_ID GITHUB_APP_PRIVATE_KEY
    run /usr/local/bin/auth-smoke --self-test
    [ "$status" -eq 0 ]
    [[ "$output" == *"auth-smoke self-test OK"* ]]
}

@test "regression-baseline: --help exits 0 and prints usage" {
    run /usr/local/bin/auth-smoke --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage: auth-smoke"* ]]
}

# ----------------------------------------------------------------------------
# PR #1605: --require-permission empty/malformed values must fail-closed
# without leaking a `ghs_` token. The Python-side `is not None` check in
# gh-mint-token.py is the canonical defense; auth-smoke.sh adds a
# bash-side reject so the empty value never reaches the Python layer.
# ----------------------------------------------------------------------------

@test "regression-1605: --require-permission \"\" rejects empty value, no token leak" {
    run /usr/local/bin/auth-smoke --require-permission "" --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    # Defense-in-depth: empty value must NOT produce a live token on stdout.
    [[ "$output" != *"ghs_"* ]]
    # Error must mention emptiness so the operator can fix the call site.
    [[ "$output" == *"empty"* ]]
}

@test "regression-1605: --require-permission= (= form, empty) rejects empty value" {
    run /usr/local/bin/auth-smoke --require-permission= --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"empty"* ]]
}

@test "regression-1605: --require-permission contents (no =) rejects malformed value" {
    run /usr/local/bin/auth-smoke --require-permission contents --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"KEY=VAL"* ]]
}

@test "regression-1605: --require-permission =write (empty key) rejects malformed value" {
    run /usr/local/bin/auth-smoke --require-permission =write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"non-empty"* ]]
}

@test "regression-1605: --require-permission contents= (empty value) rejects malformed value" {
    run /usr/local/bin/auth-smoke --require-permission contents= --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"non-empty"* ]]
}

# ----------------------------------------------------------------------------
# PR #1606: hostname regex hardening — `[^/@]*@` userinfo bound rejects
# hostname lookalikes. Without the bound, `[^/]*github\.com` accepts
# `notgithub.com` because greedy `[^/]*` swallows an arbitrary prefix.
#
# Caveat: `gh auth status` runs BEFORE the hostname regex, so with our fake
# private key these tests may exit at JWT signing rather than at the regex.
# Either path is `exit != 0`, which is the regression we want locked in
# (bad origin URL → fail-closed, end-to-end). For pinpoint regex coverage
# without minting, see the dedicated regex unit test in CI's separate
# shellcheck/shunit step (out of scope here; documented in the README).
# ----------------------------------------------------------------------------

@test "regression-1606: origin notgithub.com is rejected (hostname lookalike)" {
    git -C "$TEST_WORKSPACE" remote set-url origin "https://notgithub.com/owner/repo.git"
    run /usr/local/bin/auth-smoke --require-permission contents=read --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" != *"AUTH_OK"* ]]
}

@test "regression-1606: origin attacker@notgithub.com is rejected (userinfo+lookalike)" {
    git -C "$TEST_WORKSPACE" remote set-url origin "https://attacker@notgithub.com/owner/repo.git"
    run /usr/local/bin/auth-smoke --require-permission contents=read --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" != *"AUTH_OK"* ]]
}

@test "regression-1606: origin github.com:8080 is rejected (port suffix)" {
    git -C "$TEST_WORKSPACE" remote set-url origin "https://github.com:8080/owner/repo.git"
    run /usr/local/bin/auth-smoke --require-permission contents=read --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" != *"AUTH_OK"* ]]
}

@test "regression-1606: origin evil-github.com is rejected (hostname lookalike)" {
    git -C "$TEST_WORKSPACE" remote set-url origin "https://evil-github.com/owner/repo.git"
    run /usr/local/bin/auth-smoke --require-permission contents=read --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" != *"AUTH_OK"* ]]
}

# ----------------------------------------------------------------------------
# Template-leak detection (project memory: project_fabro_env_interpolation).
# Wrong workflow.toml syntax (`${env.X}` instead of `{{ env.X }}`) ships the
# raw template string through to the container; downstream errors (PyJWT
# "Could not parse the provided public key", App ID parse errors) are
# byte-identical to "value is empty", so catch the template shape before
# it reaches PyJWT.
# ----------------------------------------------------------------------------

@test "regression-template: literal {{ env.GITHUB_APP_PRIVATE_KEY }} is rejected" {
    export GITHUB_APP_PRIVATE_KEY='{{ env.GITHUB_APP_PRIVATE_KEY }}'
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"unsubstituted template token"* ]]
    [[ "$output" == *"GITHUB_APP_PRIVATE_KEY"* ]]
}

@test "regression-template: literal \${env.GITHUB_APP_PRIVATE_KEY} is rejected" {
    export GITHUB_APP_PRIVATE_KEY='${env.GITHUB_APP_PRIVATE_KEY}'
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"unsubstituted template token"* ]]
}

@test "regression-template: literal {{ env.GITHUB_APP_ID }} is rejected" {
    export GITHUB_APP_ID='{{ env.GITHUB_APP_ID }}'
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"unsubstituted template token"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "regression-template: literal {{ env.GITHUB_APP_INSTALLATION_ID }} is rejected" {
    export GITHUB_APP_INSTALLATION_ID='{{ env.GITHUB_APP_INSTALLATION_ID }}'
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"unsubstituted template token"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

# ----------------------------------------------------------------------------
# Required env-var checks — each must produce a named-var error (so the
# operator can identify which variable is missing without log spelunking).
# ----------------------------------------------------------------------------

@test "regression-envvars: missing ANTHROPIC_API_KEY → named-var error" {
    unset ANTHROPIC_API_KEY
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"ANTHROPIC_API_KEY"* ]]
}

@test "regression-envvars: empty ANTHROPIC_API_KEY → named-var error" {
    export ANTHROPIC_API_KEY=""
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"ANTHROPIC_API_KEY"* ]]
}

@test "new-envvars: missing GITHUB_APP_ID → named-var error" {
    unset GITHUB_APP_ID
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "new-envvars: empty GITHUB_APP_ID → named-var error" {
    export GITHUB_APP_ID=""
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_ID"* ]]
}

@test "new-envvars: missing GITHUB_APP_INSTALLATION_ID → named-var error" {
    unset GITHUB_APP_INSTALLATION_ID
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

@test "new-envvars: empty GITHUB_APP_INSTALLATION_ID → named-var error" {
    export GITHUB_APP_INSTALLATION_ID=""
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_INSTALLATION_ID"* ]]
}

@test "regression-envvars: missing GITHUB_APP_PRIVATE_KEY → named-var error" {
    unset GITHUB_APP_PRIVATE_KEY
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"GITHUB_APP_PRIVATE_KEY"* ]]
}

# ----------------------------------------------------------------------------
# PR #1602: PATH-shadow gh wrapper — `gh` MUST resolve to /usr/local/bin/gh,
# never to /usr/bin/gh (the apt binary, which has no GitHub-App auth).
# Simulate by prepending a fake-gh dir to PATH so our shim wins resolution.
# ----------------------------------------------------------------------------

@test "regression-1602: gh shadowed by fake binary (not /usr/local/bin/gh) → exit ≠ 0" {
    FAKE_GH_DIR="$(mktemp -d -t fake-gh-XXXXXX)"
    cat > "$FAKE_GH_DIR/gh" <<'EOF'
#!/usr/bin/env bash
echo "fake gh"
EOF
    chmod +x "$FAKE_GH_DIR/gh"
    PATH="$FAKE_GH_DIR:$PATH" run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    rm -rf "$FAKE_GH_DIR"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"shadowed"* || "$output" == *"/usr/local/bin/gh"* ]]
}

# ----------------------------------------------------------------------------
# PR #1601: --workspace flag (genericisation). The script defaults to
# /workspace; `--workspace PATH` lets non-issue-coder workflows point at
# their own checkout root.
# ----------------------------------------------------------------------------

@test "regression-1601: --workspace flag accepts a custom path" {
    # If --workspace doesn't reach git remote get-url, this test would fail
    # at "no origin remote" rather than later. We assert the script runs
    # past the env-var checks and reaches the workspace check (positive
    # path → mint, which fails on our fake key, but that's downstream).
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$TEST_WORKSPACE"
    [ "$status" -ne 0 ]  # fails at mint with fake PEM
    [[ "$output" != *"has no origin remote"* ]]  # but NOT at workspace check
}

@test "regression-1601: --workspace with empty path is rejected" {
    run /usr/local/bin/auth-smoke --workspace "" --require-permission contents=write
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"non-empty PATH"* ]]
}

@test "regression-1601: --workspace pointing at non-git dir → fail-closed (no token leak)" {
    # CAVEAT: with the fake PEM in setup(), the script exits at JWT signing
    # before reaching the workspace check. We can't pinpoint the
    # "no origin remote" error without real credentials, so we lock in the
    # weaker but still load-bearing property: bad workspace combined with
    # bad PEM still fails closed and never leaks a token.
    NON_GIT_DIR="$(mktemp -d -t non-git-XXXXXX)"
    run /usr/local/bin/auth-smoke --require-permission contents=write --workspace "$NON_GIT_DIR"
    rm -rf "$NON_GIT_DIR"
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
}

# ----------------------------------------------------------------------------
# Unknown / malformed CLI args
# ----------------------------------------------------------------------------

@test "regression-cli: unknown flag is rejected" {
    run /usr/local/bin/auth-smoke --bogus-flag
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"unknown argument"* ]]
}

@test "regression-cli: --require-permission with no arg is rejected" {
    run /usr/local/bin/auth-smoke --require-permission
    [ "$status" -ne 0 ]
    [[ "$output" != *"ghs_"* ]]
    [[ "$output" == *"requires"* ]]
}
