# Contributing to Skills Sandbox

Welcome! This guide covers everything you need to add, update, and maintain skills.

---

## The Golden Rule

> **Git controls code + environment. Docker enforces the environment. Everyone runs the same sandbox.**

---

## Skill Contract

Every skill lives in `skills/<name>/` and **must** include:

| File | Required | Purpose |
|------|----------|---------|
| `SKILL.md` | ✅ | What it does, how to run, dependencies used |
| `run.py` | ✅ (or custom entry) | Default entry point |
| `scripts/` | Optional | Helper scripts |
| `core/` | Optional | Reusable modules |
| `templates/` | Optional | Template files |
| `examples/` | Optional | Example inputs/outputs |
| `requirements.txt` | Optional | Skill-specific deps (still must be added to sandbox-level) |

### SKILL.md Template

```markdown
---
name: my-skill
description: "One-line description"
network: false          # Set to true if the skill needs internet
---

## What this skill does
Describe the skill clearly.

## Dependencies
- Python: library-a, library-b
- System: tool-x (if any)

## Run
\```bash
make run SKILL=my-skill ENTRY=run.py ARGS="example"
\```

## Examples
Show example input → output.
```

---

## Adding a New Skill

### Step 1: Create the skill

```bash
mkdir skills/my-skill
# Add SKILL.md and run.py (or use skill-creator)
make run SKILL=skill-creator ENTRY=scripts/init_skill.py ARGS="my-skill"
```

### Step 2: Test it

```bash
make run SKILL=my-skill
# If it needs network:
make run-net SKILL=my-skill
```

### Step 3: Handle missing dependencies

If your skill fails due to a missing library:

| What's missing | Where to add it | Then |
|---------------|----------------|------|
| Python package | `sandbox/requirements.txt` | `make build` |
| Node package | `sandbox/package.json` | `make build` |
| OS tool (apt) | `Dockerfile` → `apt-get install` block | `make build` |

### Step 4: Commit together

```bash
# Always commit skill + env changes in the same commit
git add skills/my-skill
git add sandbox/requirements.txt  # if changed
git add Dockerfile                # if changed
git commit -m "Add my-skill"
git push
```

---

## Dependency Guidelines

### Python (`sandbox/requirements.txt`)
- Add packages even if only one skill needs them — the sandbox must be reproducible.
- Group by purpose with comments (see the existing file for style).
- Pin versions only if you hit compatibility issues; otherwise keep it flexible.

### Node.js (`sandbox/package.json`)
- Same rule: add all needed packages here.
- Only used for document/artifact generation (pptxgenjs, docx, pdf-lib).

### System packages (`Dockerfile`)
- Add to the `apt-get install` block with a comment noting which skill needs it.
- Keep the list alphabetical within each comment group.

---

## Network Policy

| Mode | Command | Use when |
|------|---------|----------|
| **No network** (default) | `make run` | Most skills — PDF, DOCX, PPTX, XLSX, canvas, GIF, etc. |
| **With network** | `make run-net` | Skills that call APIs, load CDNs, install npm at runtime |

Skills that need network **must** document it in their `SKILL.md` with `network: true` in the frontmatter.

### Skills requiring network
- `mcp-builder` — Anthropic API calls for evaluation
- `web-artifacts-builder` — npm install during init
- `webapp-testing` — Playwright browser testing
- `algorithmic-art` — p5.js CDN
- `frontend-design` — font CDNs

---

## Shared Infrastructure

The **docx**, **pptx**, and **xlsx** skills share common Office XML tooling under `scripts/office/`:

```
scripts/office/
├── pack.py           # Repack directory → .docx/.pptx/.xlsx
├── unpack.py         # Unpack Office file → directory + pretty-print XML
├── validate.py       # Validate Office XML schemas
├── soffice.py        # LibreOffice runner with sandbox shim
├── helpers/          # merge_runs.py, simplify_redlines.py
├── validators/       # base.py, docx.py, pptx.py, redlining.py
└── schemas/          # ISO/IEC 29500, ECMA, MCE schemas
```

If you modify anything in `scripts/office/`, test all three skills (docx, pptx, xlsx).

---

## Code Style

- Python: follow PEP 8, use type hints where practical.
- Scripts should be runnable standalone (`if __name__ == "__main__":` pattern).
- Use `os.environ["SKILL_DIR"]` and `os.environ["SKILL_ARGS"]` from the runner.
- Print output with clear prefixes: `[skill-name] message`.

---

## Troubleshooting Workflow

```
1. make run SKILL=foo → fails?
2. Read the error.
3. Missing import?   → Add to requirements.txt → make build → retry
4. Missing OS tool?  → Add to Dockerfile → make build → retry
5. Needs network?    → make run-net SKILL=foo
6. Still broken?     → make shell → debug interactively
```
