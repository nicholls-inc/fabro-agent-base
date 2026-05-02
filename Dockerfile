# fabro-agent-base: shared GitHub-App auth surface for fabro coding-agent workflows.
#
# This image provides the reusable authentication primitives every fabro
# coding-agent workflow needs: a lazy-mint installation-token minter, a
# PATH-shadow `gh` wrapper that injects GH_TOKEN on every invocation, a git
# credential helper that hands out the same token to git over HTTPS, and a
# fail-closed `auth-smoke` gate workflows invoke before any LLM cost. Build
# context is the repo root (i.e. `docker build .` from the repo top level)
# so `COPY docker/X` resolves correctly.
#
# Intended distribution: pulled from
# `ghcr.io/nicholls-inc/fabro-agent-base:<semver>` and consumed via `FROM` in
# downstream workflow images. Do not bake project-specific dependencies
# (uv, ruff, pre-commit, language packages) into this image — consumers add
# their own per-workflow tooling on top. See README.md for the runtime
# env-var contract and the frozen inter-image surface.

FROM python:3.13-slim

# Use bash with pipefail for all RUN instructions so pipe failures (e.g. a
# failing curl in the gh CLI keyring step) surface at the correct layer
# rather than being masked by the downstream command's exit code.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

LABEL org.opencontainers.image.source="https://github.com/nicholls-inc/fabro-agent-base"
LABEL org.opencontainers.image.description="Reusable GitHub-App auth surface for fabro coding-agent workflows"
LABEL org.opencontainers.image.licenses="MIT"

# --- System tools ---
# Deliberately minimal: only what the auth surface itself needs. ripgrep,
# language toolchains, and project-specific binaries belong in consumer
# images, not here.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- GitHub CLI ---
# This is the highest-value, most-fragile block in the image — exactly why
# it lives in the shared base. The keyring + repo + apt install dance is
# replicated verbatim from the upstream cli.github.com instructions.
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# --- Runtime deps for gh-mint-token ---
# PyJWT signs the App JWT, requests calls api.github.com, cryptography is
# PyJWT's RS256 backend. No `uv` here — consumers pull in uv themselves if
# they need it.
RUN pip install --no-cache-dir PyJWT requests cryptography

# --- GitHub App auth surface ---
# The wrapper at /usr/local/bin/gh shadows the apt-installed /usr/bin/gh on
# PATH; on every invocation it lazy-mints / refreshes a GitHub App
# installation token via gh-mint-token, exports GH_TOKEN, then exec's the
# real gh. git operations against github.com use the credential helper at
# /usr/local/bin/git-credential-github-app, registered globally via
# /etc/gitconfig. ENTRYPOINT pre-warms the cache so the first invocation
# doesn't pay the ~200 ms mint latency. auth-smoke is a fail-closed gate
# that consuming workflows invoke before any LLM cost; it accepts repeatable
# `--require-permission KEY=VAL` flags and a `--workspace PATH` flag.
COPY docker/gh-mint-token.py /usr/local/bin/gh-mint-token
COPY docker/gh-wrapper.sh /usr/local/bin/gh
COPY docker/git-credential-github-app.sh /usr/local/bin/git-credential-github-app
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/auth-smoke.sh /usr/local/bin/auth-smoke
RUN chmod 0755 /usr/local/bin/gh-mint-token \
                /usr/local/bin/gh \
                /usr/local/bin/git-credential-github-app \
                /usr/local/bin/entrypoint.sh \
                /usr/local/bin/auth-smoke \
    && printf '[credential "https://github.com"]\n\thelper = /usr/local/bin/git-credential-github-app\n' > /etc/gitconfig

# --- Smoke test: fail the build if any required tool is broken ---
# `gh --version` calls the apt binary directly (not the wrapper); the
# wrapper requires GITHUB_APP_PRIVATE_KEY in env to mint, and that's a
# runtime secret, not present at image build time. We verify the wrapper
# is on PATH separately via `command -v gh`. The four `--self-test`
# invocations exercise each script's shape without needing real secrets.
RUN /usr/bin/gh --version \
    && python3 -c "import jwt; print('PyJWT OK')" \
    && command -v gh | grep -qx "/usr/local/bin/gh" \
    && /usr/local/bin/gh-mint-token --self-test \
    && /usr/local/bin/git-credential-github-app --self-test \
    && /usr/local/bin/auth-smoke --self-test

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
