# 🧰 Skills Sandbox

A reproducible, Docker-based sandbox where every skill runs the same way on every machine.  
Clone → build → run. That's it.

---

## Prerequisites

| Tool | Min version | Install |
|------|------------|---------|
| **Docker Desktop** | 4.x | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) |
| **Git** | 2.x | Comes with macOS / `apt install git` |

> **No need** to install Python, Node, LibreOffice, or any other tool on your host — everything runs inside the container.

---

## Quick Start

```bash
# 1. Clone
git clone <YOUR_REPO_URL>
cd skills-sandbox

# 2. Build the sandbox image (first time takes ~3-5 min)
make build

# 3. Run the template skill to verify everything works
make run SKILL=_template ENTRY=run.py ARGS="hello world"
# → [template] args=hello world
# → [template] skill_dir=/workspace/skills/_template
```

---

## Commands

```bash
make help          # Show all commands
make build         # Build / rebuild the Docker image
make run           # Run a skill (no network)
make run-net       # Run a skill WITH network access
make shell         # Open a bash shell in the sandbox
make shell-net     # Bash shell WITH network access
make list          # List all available skills
make clean         # Remove stopped containers & images
```

### Running a skill

```bash
# Pattern
make run SKILL=<name> ENTRY=<script> ARGS="<arguments>"

# Examples
make run SKILL=_template ENTRY=run.py ARGS="hello world"
make run SKILL=pdf ENTRY=scripts/check_fillable_fields.py ARGS="myfile.pdf"
make run SKILL=xlsx ENTRY=scripts/recalc.py ARGS="spreadsheet.xlsx"
make run SKILL=pptx ENTRY=scripts/thumbnail.py ARGS="deck.pptx"
make run SKILL=slack-gif-creator ENTRY=core/gif_builder.py
```

### Skills that need network

Some skills fetch from CDNs, install npm packages at runtime, or call APIs.  
Use `make run-net` for those:

```bash
make run-net SKILL=mcp-builder ENTRY=scripts/evaluation.py
make run-net SKILL=webapp-testing ENTRY=scripts/with_server.py
make run-net SKILL=web-artifacts-builder ENTRY=scripts/init-artifact.sh
```

---

## 📂 Skills Catalog

### Document Skills

| Skill | What it does | Language | Entry points |
|-------|-------------|----------|-------------|
| **docx** | Create, edit & analyze Word documents | Python + Node | `scripts/office/unpack.py`, `scripts/office/pack.py`, `scripts/comment.py` |
| **pptx** | Create, edit & analyze PowerPoint decks | Python + Node | `scripts/add_slide.py`, `scripts/thumbnail.py`, `scripts/clean.py` |
| **xlsx** | Create, edit & analyze Excel spreadsheets | Python | `scripts/recalc.py`, `scripts/office/unpack.py` |
| **pdf** | Read, create, merge, split, OCR, fill forms | Python | `scripts/check_fillable_fields.py`, `scripts/fill_fillable_fields.py`, `scripts/convert_pdf_to_images.py` |

### Creative Skills

| Skill | What it does | Language | Network |
|-------|-------------|----------|---------|
| **algorithmic-art** | Generative art with p5.js | JavaScript | ✅ CDN |
| **canvas-design** | Museum-quality PDF/PNG art (84 bundled fonts) | Python | ❌ |
| **slack-gif-creator** | Animated GIFs optimized for Slack | Python | ❌ |
| **theme-factory** | 10 pre-built color+font themes | Markdown (reference) | ❌ |
| **brand-guidelines** | Anthropic brand colors & typography | Markdown (reference) | ❌ |

### Web & Frontend Skills

| Skill | What it does | Language | Network |
|-------|-------------|----------|---------|
| **frontend-design** | Production-grade frontend UI guidelines | Reference | ✅ fonts |
| **web-artifacts-builder** | React + TS + Tailwind → single HTML artifact | TypeScript | ✅ npm |
| **webapp-testing** | Browser automation with Playwright | Python | ✅ localhost |

### Communication & Writing Skills

| Skill | What it does | Language | Network |
|-------|-------------|----------|---------|
| **doc-coauthoring** | 3-stage collaborative doc writing workflow | Workflow (no code) | ❌ |
| **internal-comms** | 3P updates, newsletters, FAQ templates | Markdown (reference) | ❌ |

### Developer / Meta Skills

| Skill | What it does | Language | Network |
|-------|-------------|----------|---------|
| **mcp-builder** | Build MCP servers + evaluation harness | Python + TS | ✅ API |
| **skill-creator** | Scaffold, package & validate new skills | Python | ❌ |

---

## 🏗 Project Structure

```
skills-sandbox/
├── skills/                    # ← All skills live here
│   ├── _template/             #    Starter template
│   ├── docx/                  #    Word documents
│   ├── pptx/                  #    PowerPoint decks
│   ├── xlsx/                  #    Excel spreadsheets
│   ├── pdf/                   #    PDF processing
│   ├── algorithmic-art/       #    Generative art
│   ├── brand-guidelines/      #    Brand reference
│   ├── canvas-design/         #    PDF/PNG art
│   ├── doc-coauthoring/       #    Doc writing workflow
│   ├── frontend-design/       #    Frontend guidelines
│   ├── internal-comms/        #    Internal comms templates
│   ├── mcp-builder/           #    MCP server builder
│   ├── skill-creator/         #    Skill scaffolding
│   ├── slack-gif-creator/     #    Animated GIF builder
│   ├── theme-factory/         #    Theme definitions
│   ├── web-artifacts-builder/ #    React → HTML bundler
│   └── webapp-testing/        #    Playwright testing
│
├── sandbox/                   # ← Shared runtime
│   ├── runner/
│   │   ├── __init__.py
│   │   └── cli.py             #    Skill runner entrypoint
│   ├── requirements.txt       #    Python dependencies
│   └── package.json           #    Node.js dependencies
│
├── Dockerfile                 #    Container image definition
├── docker-compose.yml         #    Service config + hardening
├── Makefile                   #    One-liner commands
├── README.md                  #    ← You are here
└── CONTRIBUTING.md            #    How to add / update skills
```

---

## 🔒 Security Model (Phase 1: Teammates-Only)

The container runs with basic hardening suitable for a trusted team:

| Control | Setting |
|---------|---------|
| **Non-root user** | `sandbox` (UID 1000) |
| **Capabilities** | All dropped (`cap_drop: ALL`) |
| **Privilege escalation** | Blocked (`no-new-privileges`) |
| **Network** | Disabled by default (`network_mode: none`) |
| **Memory limit** | 2 GB |
| **CPU limit** | 2 cores |
| **PID limit** | 256 processes |

> Use `make run-net` or `make shell-net` when you need network access.

---

## 🔧 Adding Dependencies

When a skill needs something that's not in the sandbox:

### Python library missing
1. Add it to `sandbox/requirements.txt`
2. `make build`
3. Verify: `make run SKILL=<skill_name> ...`
4. Commit + push

### OS tool missing (ffmpeg, poppler, etc.)
1. Add it to the `apt-get install` block in `Dockerfile`
2. `make build`
3. Verify: `make run SKILL=<skill_name> ...`
4. Commit + push

### Node.js package missing
1. Add it to `sandbox/package.json`
2. `make build`
3. Verify: `make run SKILL=<skill_name> ...`
4. Commit + push

> **Always commit env changes** so everyone's sandbox stays in sync.

---

## 🧩 Adding a New Skill

```bash
# 1. Create the folder
mkdir skills/my-new-skill

# 2. Add required files
#    SKILL.md  — what it does + how to run
#    run.py    — default entry point (or any script)

# 3. Test it
make run SKILL=my-new-skill

# 4. If it needs new deps, update requirements.txt / Dockerfile, rebuild

# 5. Commit everything together
git add skills/my-new-skill sandbox/requirements.txt  # if changed
git commit -m "Add my-new-skill"
git push
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

---

## What's Installed in the Sandbox

<details>
<summary><strong>System packages</strong> (click to expand)</summary>

- **Build tools**: git, curl, gcc, build-essential
- **Node.js**: nodejs, npm, pnpm
- **LibreOffice**: headless Writer, Calc, Impress (docx/pptx/xlsx → PDF)
- **Poppler**: pdftotext, pdftoppm, pdfimages
- **Pandoc**: document format conversion
- **qpdf**: PDF low-level manipulation
- **Tesseract OCR**: text extraction from images
- **FFmpeg**: video/audio/GIF processing
- **Ghostscript**: PDF rendering backend
- **Playwright deps**: Chromium browser automation libraries

</details>

<details>
<summary><strong>Python packages</strong> (click to expand)</summary>

Core: pytest, rich, python-dotenv, pydantic, pyyaml  
Office: python-docx, python-pptx, openpyxl, pandas, defusedxml, markitdown  
PDF: reportlab, pypdf, pdfplumber, pypdfium2, pdf2image, pytesseract, Pillow  
GIF: imageio, imageio-ffmpeg, numpy  
MCP: anthropic, mcp  
Web: playwright  

</details>

<details>
<summary><strong>Node.js packages</strong> (click to expand)</summary>

pptxgenjs, docx, pdf-lib

</details>

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Cannot connect to the Docker daemon` | Start Docker Desktop |
| Build fails on `apt-get` | Check internet; re-run `make build` |
| Skill says "module not found" | Add the package to `requirements.txt` or `package.json`, then `make build` |
| Skill needs network but times out | Use `make run-net` instead of `make run` |
| Permission denied on output files | Files created in container are owned by UID 1000; run `sudo chown -R $USER .` on host if needed |
| Slow first build | Normal (~3-5 min). Subsequent builds use Docker layer cache and are fast |