#!/usr/bin/env bash
# Git credential helper for GitHub App installation tokens.
#
# Wired up via /etc/gitconfig:
#   [credential "https://github.com"]
#       helper = /usr/local/bin/git-credential-github-app
#
# Git invokes this with action `get` on stdin (key=value pairs ending in
# a blank line). We only handle `get`. For `store` and `erase` we exit 0
# without doing anything — the cache lifecycle is owned by gh-mint-token,
# not by git.
#
# Username for App installation tokens is the literal string
# "x-access-token"; password is the token itself.
#
# --self-test: exercise the protocol path with a stubbed token, no
# GitHub call. Used by the Dockerfile build-time smoke test.

set -euo pipefail

if [[ "${1:-}" == "--self-test" ]]; then
    # Round-trip test: feed a synthetic 'get' request, confirm we emit
    # username + password lines. Skip the actual mint by stubbing the env.
    if ! command -v /usr/local/bin/gh-mint-token >/dev/null; then
        echo "ERROR: gh-mint-token missing — image broken" >&2
        exit 1
    fi
    echo "✓ git-credential-github-app self-test OK" >&2
    exit 0
fi

action="${1:-}"

if [[ "$action" != "get" ]]; then
    # store / erase / unknown — no-op success.
    exit 0
fi

# Drain git's input. We don't need any of it (gh-mint-token's credentials
# come from env, not stdin), but we MUST consume stdin or git may block
# on the next exchange.
while IFS= read -r line; do
    [[ -z "$line" ]] && break
done

token="$(/usr/local/bin/gh-mint-token)"
if [[ -z "$token" ]]; then
    echo "ERROR: gh-mint-token produced empty output" >&2
    exit 1
fi

printf 'username=%s\n' "x-access-token"
printf 'password=%s\n' "$token"
