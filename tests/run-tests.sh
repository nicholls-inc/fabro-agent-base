#!/usr/bin/env bash
# Run the full bats regression suite for fabro-agent-base.
#
# Invoked as the test image's CMD. Exits non-zero on any failing test so
# `docker run` surfaces the failure to CI without further plumbing.
set -euo pipefail

cd "$(dirname "$0")"

echo "Running fabro-agent-base bats regression suite..."
echo "  bats: $(bats --version)"
echo "  base image binaries:"
echo "    auth-smoke:    $(command -v auth-smoke || echo 'MISSING')"
echo "    gh-mint-token: $(command -v gh-mint-token || echo 'MISSING')"
echo "    gh:            $(command -v gh || echo 'MISSING')"
echo

bats test_auth_smoke.bats test_gh_mint_token.bats
