# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# omni-secret-scanner — multi-stage Docker image
# ---------------------------------------------------------------------------
# Build:  docker build -t omni-secret-scanner -f docker/Dockerfile .
# Run:    docker run --rm -v $(pwd):/repo omni-secret-scanner --format json
# ---------------------------------------------------------------------------

# ── Stage 1: builder ────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --upgrade pip && \
    pip install build && \
    python -m build --wheel --outdir /dist


# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Non-root user for security
RUN adduser --disabled-password --gecos "" scanner

# Install git (required for history scanning)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Install the wheel from builder
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

USER scanner
WORKDIR /repo

ENTRYPOINT ["omni-scan"]
CMD ["--help"]
