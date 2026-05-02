#!/usr/bin/env bash
# Container entrypoint: pre-warm the GitHub App token cache so the first
# wrapper invocation doesn't pay the ~200 ms mint latency, and fail-fast
# if required env is missing.
#
# Empirical note: it's not yet confirmed whether Fabro's docker provider
# (v0.220+) honours ENTRYPOINT — it may invoke commands via `docker exec`
# rather than `docker run`, in which case ENTRYPOINT only fires on the
# implicit `docker run` that starts the container. Either way the wrapper
# does lazy mint on first call, so this entrypoint is a pre-warm
# optimization rather than a correctness requirement.

set -euo pipefail

# Best-effort pre-warm. We do NOT fail-fast on missing
# GITHUB_APP_PRIVATE_KEY here — that would block image introspection
# (`docker run --rm fabro-agent:latest sh`) and provides no real
# protection over what the auth_smoke Fabro node already enforces. The
# wrapper exits 1 with a clear error when a real gh/git call needs the
# token and can't mint one; auth_smoke turns that into a fail-closed
# workflow gate before any LLM cost.
/usr/local/bin/gh-mint-token >/dev/null 2>&1 || true

exec "$@"
