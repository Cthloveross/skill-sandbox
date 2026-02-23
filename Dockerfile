FROM python:3.11-slim

# Basic OS deps (keep minimal; add only when needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential \
    nodejs npm \
  && rm -rf /var/lib/apt/lists/*

# Non-root user (important)
RUN useradd -m -u 1000 sandbox
USER sandbox
WORKDIR /workspace

# Python deps
COPY --chown=sandbox:sandbox sandbox/requirements.txt /workspace/sandbox/requirements.txt
RUN pip install --no-cache-dir -r /workspace/sandbox/requirements.txt

# Node deps (optional)
COPY --chown=sandbox:sandbox sandbox/package.json /workspace/sandbox/package.json
RUN cd /workspace/sandbox && npm install

# Skill runner
COPY --chown=sandbox:sandbox sandbox/runner /workspace/sandbox/runner

ENTRYPOINT ["python", "-m", "sandbox.runner.cli"]
