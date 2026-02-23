FROM python:3.11-slim

# ──────────────────────────────────────────────
# 1. System packages
#    Edit this block when a skill needs a new OS-level tool,
#    then run `make build` and commit.
# ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    git curl ca-certificates build-essential gcc \
    # Node.js (for docx/pptx/web-artifacts-builder)
    nodejs npm \
    # LibreOffice headless (docx, pptx, xlsx – export to PDF, recalc formulas)
    libreoffice-common libreoffice-writer libreoffice-calc libreoffice-impress \
    # Poppler utils – pdftotext, pdftoppm, pdfimages (pdf, pptx, docx)
    poppler-utils \
    # Pandoc – doc conversion (docx)
    pandoc \
    # qpdf – PDF manipulation (pdf)
    qpdf \
    # Tesseract OCR (pdf – OCR extraction)
    tesseract-ocr \
    # FFmpeg (slack-gif-creator – video/gif processing)
    ffmpeg \
    # Ghostscript (pdf – pdf2image backend)
    ghostscript \
    # Playwright system deps (webapp-testing)
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 \
  && rm -rf /var/lib/apt/lists/*

# Install pnpm globally (web-artifacts-builder)
RUN npm install -g pnpm

# ──────────────────────────────────────────────
# 2. Non-root user
# ──────────────────────────────────────────────
RUN useradd -m -u 1000 sandbox
USER sandbox
WORKDIR /workspace

# ──────────────────────────────────────────────
# 3. Python dependencies
#    Edit sandbox/requirements.txt, then `make build`.
# ──────────────────────────────────────────────
COPY --chown=sandbox:sandbox sandbox/requirements.txt /workspace/sandbox/requirements.txt
RUN pip install --no-cache-dir -r /workspace/sandbox/requirements.txt

# Install Playwright browsers (webapp-testing)
RUN python -m playwright install chromium 2>/dev/null || true

# ──────────────────────────────────────────────
# 4. Node.js dependencies
#    Installed to ~/node_packages (outside /workspace)
#    so the volume mount doesn't hide them.
#    Edit sandbox/package.json, then `make build`.
# ──────────────────────────────────────────────
COPY --chown=sandbox:sandbox sandbox/package.json /home/sandbox/node_packages/package.json
RUN cd /home/sandbox/node_packages && npm install
ENV NODE_PATH=/home/sandbox/node_packages/node_modules

# ──────────────────────────────────────────────
# 5. Skill runner CLI
# ──────────────────────────────────────────────
COPY --chown=sandbox:sandbox sandbox/runner /workspace/sandbox/runner

ENTRYPOINT ["python", "-m", "sandbox.runner.cli"]
