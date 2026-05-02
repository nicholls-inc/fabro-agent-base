#!/usr/bin/env bash
# PATH-shadow wrapper for the GitHub CLI.
#
# Installed at /usr/local/bin/gh ahead of the apt-shipped /usr/bin/gh on
# PATH. Every invocation lazy-mints a GitHub App installation token (via
# /usr/local/bin/gh-mint-token), exports GH_TOKEN, then exec's the real gh.
#
# Why a wrapper rather than a workflow setup stage: gh has no native
# pre-command hook and no native GitHub-App auth (cli/cli#8747). Tokens
# expire after 1h; on long workflow runs the single-mint-at-start pattern
# was racing the timer.

set -euo pipefail

REAL_GH="/usr/bin/gh"

# Defense against accidental recursion: if PATH somehow puts us ahead of
# ourselves, we'd loop forever. Verify the real gh exists.
if [[ ! -x "$REAL_GH" ]]; then
    echo "ERROR: real gh binary missing at $REAL_GH (image build broken)" >&2
    exit 1
fi

# gh-mint-token prints the token on stdout. It handles cache freshness
# itself; we don't second-guess. Guard against a future regression where
# the minter exits 0 with empty stdout — without this check, real gh would
# run unauthenticated against public endpoints or fall through to keyring
# auth, defeating the App-identity contract.
GH_TOKEN="$(/usr/local/bin/gh-mint-token)"
if [[ -z "$GH_TOKEN" ]]; then
    echo "ERROR: gh-mint-token produced empty output — refusing to exec gh unauthenticated" >&2
    exit 1
fi
export GH_TOKEN

exec "$REAL_GH" "$@"
