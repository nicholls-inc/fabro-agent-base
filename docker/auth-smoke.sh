#!/usr/bin/env bash
# Generic GitHub-App auth smoke for fabro-agent-base.
#
# Installed in the base image as /usr/local/bin/auth-smoke. Per-workflow
# consumer scripts are thin wrappers, e.g.:
#     exec /usr/local/bin/auth-smoke --require-permission contents=write
#
# The image-baked gh wrapper handles minting; this stage verifies it
# works against the real GitHub API before any LLM cost is incurred.
# Same fail-closed semantics as the previous mint-based gate, but
# exercises a richer surface: bad credentials → 401, broken wrapper /
# wrong PATH → "missing GH_TOKEN", network failure → URL error.
#
# Also fail-fasts on missing ANTHROPIC_API_KEY — every Agent stage that
# pulls this base image consumes it, and an empty value would burn the
# Docker startup before surfacing a Claude API 401. (Workflows that
# don't use Claude wouldn't pull the base image; the env-var check is
# a safe over-spec.)
#
# Routing contract (inter-image): prints `AUTH_OK` to stdout on
# success, and only on success. The downstream cond_auth_ok diamond
# routes on `command.output contains AUTH_OK` (Command-bridge pattern).
# DO NOT change the AUTH_OK token without coordinating with all
# consuming workflows — it is the load-bearing routing string.
# Status messages go to stderr so they don't pollute the routing token.
# `outcome = succeeded` cannot be used here — it evaluates against the
# diamond's own outcome (always succeeded), not this script's exit code,
# so it would route to analyze even on failure (run
# 01KQMEAHBBXNWWKYM0PQWD4755 burned LLM tokens that way 2026-05-02).
#
# CLI:
#   --require-permission KEY=VAL  Repeatable. Each forwards to one
#                                 `gh-mint-token --require-permission KEY=VAL`
#                                 call. Empty/malformed values are rejected
#                                 (fail-closed; see below). Zero flags is
#                                 allowed for metadata-only workflows.
#   --workspace PATH              Workspace root for `git remote get-url
#                                 origin`. Defaults to /workspace.
#   --self-test                   Offline check — verifies the three
#                                 image-baked binaries are on PATH at the
#                                 expected paths, prints OK to stderr,
#                                 exits 0. NO env vars required, NO
#                                 GitHub API call. Used by the Dockerfile
#                                 build smoke to catch mis-installed
#                                 binaries.
#   -h, --help                    Print usage and exit 0.

set -euo pipefail

usage() {
    cat <<USAGE >&2
Usage: auth-smoke [OPTIONS]

Verify GitHub-App + Anthropic auth round-trips before LLM cost is
incurred. Prints AUTH_OK to stdout on success.

Options:
  --require-permission KEY=VAL  Required permission (repeatable).
                                Forwards to gh-mint-token. Empty or
                                malformed values are rejected.
  --workspace PATH              Workspace root for origin remote
                                (default: /workspace).
  --self-test                   Offline check that image-baked binaries
                                exist at expected paths. Exits 0 on OK.
  -h, --help                    Show this help and exit.

Environment:
  ANTHROPIC_API_KEY             Required (non-empty).
  GITHUB_APP_ID                 Required (non-empty, no template token).
  GITHUB_APP_INSTALLATION_ID    Required (non-empty, no template token).
  GITHUB_APP_PRIVATE_KEY        Required (non-empty, no template token).
USAGE
}

REQUIRED_PERMISSIONS=()
WORKSPACE="/workspace"
SELF_TEST=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --require-permission)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --require-permission requires a KEY=VAL argument" >&2
                exit 1
            fi
            perm_value="$2"
            if [[ -z "$perm_value" ]]; then
                echo "ERROR: --require-permission given an empty value — refusing to forward an empty permission spec to gh-mint-token (would silently fail-open)." >&2
                exit 1
            fi
            if [[ "$perm_value" != *=* ]]; then
                echo "ERROR: --require-permission must be of the form KEY=VAL (got: '$perm_value')" >&2
                exit 1
            fi
            # Reject malformed values where key or val is empty (e.g. '=write' or 'contents=').
            perm_key="${perm_value%%=*}"
            perm_val="${perm_value#*=}"
            if [[ -z "$perm_key" || -z "$perm_val" ]]; then
                echo "ERROR: --require-permission KEY=VAL must have non-empty key and value (got: '$perm_value')" >&2
                exit 1
            fi
            REQUIRED_PERMISSIONS+=("$perm_value")
            shift 2
            ;;
        --require-permission=*)
            perm_value="${1#--require-permission=}"
            if [[ -z "$perm_value" ]]; then
                echo "ERROR: --require-permission given an empty value — refusing to forward an empty permission spec to gh-mint-token (would silently fail-open)." >&2
                exit 1
            fi
            if [[ "$perm_value" != *=* ]]; then
                echo "ERROR: --require-permission must be of the form KEY=VAL (got: '$perm_value')" >&2
                exit 1
            fi
            perm_key="${perm_value%%=*}"
            perm_val="${perm_value#*=}"
            if [[ -z "$perm_key" || -z "$perm_val" ]]; then
                echo "ERROR: --require-permission KEY=VAL must have non-empty key and value (got: '$perm_value')" >&2
                exit 1
            fi
            REQUIRED_PERMISSIONS+=("$perm_value")
            shift
            ;;
        --workspace)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                echo "ERROR: --workspace requires a non-empty PATH argument" >&2
                exit 1
            fi
            WORKSPACE="$2"
            shift 2
            ;;
        --workspace=*)
            WORKSPACE="${1#--workspace=}"
            if [[ -z "$WORKSPACE" ]]; then
                echo "ERROR: --workspace requires a non-empty PATH argument" >&2
                exit 1
            fi
            shift
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Self-test mode — offline check used by Dockerfile build smoke. Verifies
# the three image-baked binaries exist at the expected paths so a mis-
# installed image fails the docker build, not the first real run.
# ---------------------------------------------------------------------------
if [[ "$SELF_TEST" -eq 1 ]]; then
    for bin in /usr/local/bin/gh-mint-token /usr/local/bin/gh /usr/local/bin/git-credential-github-app; do
        if [[ ! -x "$bin" ]]; then
            echo "ERROR: self-test failed — $bin is missing or not executable" >&2
            exit 1
        fi
    done
    echo "✓ auth-smoke self-test OK" >&2
    exit 0
fi

# ---------------------------------------------------------------------------
# Env-var checks. Each required var has two failure modes:
#   1. unset/empty → named-var error
#   2. contains an unsubstituted `{{ env.X }}` or `${env.X}` template
#      token → template-leak error. Wrong workflow.toml syntax ships the
#      raw template string through to the container; downstream errors
#      (PyJWT "Could not parse the provided public key", App ID parse
#      errors) are byte-identical to "value is empty", so catch the
#      template shape here. Load-bearing per project memory
#      `project_fabro_env_interpolation`.
# ---------------------------------------------------------------------------

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "ERROR: ANTHROPIC_API_KEY is not set or empty — export it before running fabro." >&2
    exit 1
fi

if [[ "${GITHUB_APP_ID:-}" == *'{{ env.'* || "${GITHUB_APP_ID:-}" == *'${env.'* ]]; then
    echo "ERROR: GITHUB_APP_ID contains an unsubstituted template token — fabro did not interpolate the env var. Check workflow.toml syntax (must be {{ env.X }}, not \${env.X}) and verify the fabro server has the var exported." >&2
    exit 1
fi

if [[ -z "${GITHUB_APP_ID:-}" ]]; then
    echo "ERROR: GITHUB_APP_ID is not set or empty — the gh wrapper cannot mint an installation token without it." >&2
    exit 1
fi

if [[ "${GITHUB_APP_INSTALLATION_ID:-}" == *'{{ env.'* || "${GITHUB_APP_INSTALLATION_ID:-}" == *'${env.'* ]]; then
    echo "ERROR: GITHUB_APP_INSTALLATION_ID contains an unsubstituted template token — fabro did not interpolate the env var. Check workflow.toml syntax (must be {{ env.X }}, not \${env.X}) and verify the fabro server has the var exported." >&2
    exit 1
fi

if [[ -z "${GITHUB_APP_INSTALLATION_ID:-}" ]]; then
    echo "ERROR: GITHUB_APP_INSTALLATION_ID is not set or empty — the gh wrapper cannot mint an installation token without it." >&2
    exit 1
fi

# Detect literal-token leakage from an unsubstituted {{ env.X }} or
# ${env.X}. Either form ships the raw template token through to the
# container; the JWT layer's "Could not parse the provided public key"
# is byte-identical to "key is empty", so catch the template shape here
# before it reaches PyJWT.
if [[ "${GITHUB_APP_PRIVATE_KEY:-}" == *'{{ env.'* || "${GITHUB_APP_PRIVATE_KEY:-}" == *'${env.'* ]]; then
    echo "ERROR: GITHUB_APP_PRIVATE_KEY contains an unsubstituted template token — fabro did not interpolate the env var. Check workflow.toml syntax (must be {{ env.X }}, not \${env.X}) and verify the fabro server has the var exported." >&2
    exit 1
fi

if [[ -z "${GITHUB_APP_PRIVATE_KEY:-}" ]]; then
    echo "ERROR: GITHUB_APP_PRIVATE_KEY is not set or empty — the gh wrapper cannot mint an installation token without it." >&2
    exit 1
fi

# Confirm the wrapper is on PATH and resolves to the image-baked shim,
# not the apt-installed binary (which has no GitHub-App auth and would
# fail later with "missing GH_TOKEN").
if ! command -v gh >/dev/null 2>&1; then
    echo "ERROR: gh CLI is not on PATH — the sandbox image is missing or wrong (expected fabro-agent:latest)." >&2
    exit 1
fi
GH_PATH="$(command -v gh)"
if [[ "$GH_PATH" != "/usr/local/bin/gh" ]]; then
    echo "ERROR: gh on PATH resolves to $GH_PATH, not /usr/local/bin/gh — the GitHub-App wrapper is being shadowed." >&2
    exit 1
fi

# `gh auth status` reports the source of the token (env vs hosts.yml) and
# whether it's valid. We pipe through the wrapper, so this also exercises
# the lazy-mint code path on a cold cache.
gh auth status >&2

# Derive owner/repo from the workspace's origin remote. Fabro's docker
# provider clones the target repo into the workspace before any stage runs
# (see workflow.toml [run.sandbox]), so origin always points at the repo
# the workflow is operating on. The wrapper's mint targets the same App
# installation regardless, but we need owner/repo to verify the token
# actually round-trips against *this* repo.
ORIGIN_URL="$(git -C "$WORKSPACE" remote get-url origin 2>/dev/null || true)"
if [[ -z "$ORIGIN_URL" ]]; then
    echo "ERROR: $WORKSPACE has no origin remote — cannot determine target repo. Fabro should have cloned the repo before this stage; check [run.sandbox] in workflow.toml." >&2
    exit 1
fi

# Strip an optional `.git` suffix; GitHub returns 404 if it's appended to
# the API path. Match both https://[creds@]github.com/owner/repo and
# git@github.com:owner/repo forms; reject anything else (including
# enterprise hosts) — the App is bound to github.com.
ORIGIN_URL="${ORIGIN_URL%.git}"
# The userinfo group `([^/@]*@)?` is bounded by `@` so it cannot eat the
# host segment. Without that bound, `[^/]*github\.com` accepts hostname
# lookalikes (`notgithub.com`, `evil-github.com`) because greedy `[^/]*`
# can consume an arbitrary prefix before the literal `github.com`. Reject
# those — the App is bound to the public github.com host. BASH_REMATCH
# index 1 is the optional userinfo, 2 is owner, 3 is repo.
if [[ "$ORIGIN_URL" =~ ^https?://([^/@]*@)?github\.com/([^/]+)/([^/]+)$ ]]; then
    OWNER="${BASH_REMATCH[2]}"
    REPO="${BASH_REMATCH[3]}"
elif [[ "$ORIGIN_URL" =~ ^git@github\.com:([^/]+)/([^/]+)$ ]]; then
    OWNER="${BASH_REMATCH[1]}"
    REPO="${BASH_REMATCH[2]}"
else
    echo "ERROR: cannot parse github.com owner/repo from origin URL: $ORIGIN_URL" >&2
    exit 1
fi

# Permissions check (fail-closed before any GitHub API call). Reads the
# permissions map cached at mint time by gh-mint-token. Each permission
# was passed in via --require-permission; iterate so different workflows
# can request different policies (issue-coder needs contents=write; a
# read-only auditor might request only metadata=read; a metadata-only
# probe can pass zero flags). PR creation requires `pull_requests:write`
# separately — let consuming workflows decide whether to require it.
if [[ "${#REQUIRED_PERMISSIONS[@]}" -gt 0 ]]; then
    for perm in "${REQUIRED_PERMISSIONS[@]}"; do
        echo "✓ Required permission: $perm" >&2
        /usr/local/bin/gh-mint-token --require-permission "$perm"
    done
fi

# Real round-trip — confirms the token is accepted by GitHub *for this
# repo*. App installation tokens have no user identity (so /user 403s),
# but /repos/{owner}/{repo} works with installation auth and only needs
# metadata:read, which is implicit for any repo the App is installed on.
# A 404 here means the App is not installed on the target repo; the
# wrapper would still mint a token successfully but every gh/git call
# against the repo would fail downstream.
FULL_NAME="$(gh api "/repos/${OWNER}/${REPO}" --jq .full_name)"

if [[ -z "$FULL_NAME" ]]; then
    echo "ERROR: gh api /repos/${OWNER}/${REPO} returned empty full_name — App likely not installed on this repo, or token rejected" >&2
    exit 1
fi

echo "✓ GitHub App auth verified for $FULL_NAME" >&2

# Routing token — must be the only thing on stdout. cond_auth_ok routes
# on `command.output contains AUTH_OK`.
echo "AUTH_OK"
