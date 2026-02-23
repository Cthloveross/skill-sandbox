# Skills Sandbox (Phase 1: teammates-only)

## Prereqs
- Docker Desktop
- Git

## Build
```bash
make build
```

## Run a skill
```bash
make run SKILL=_template ENTRY=run.py ARGS="hello world"
```

## Add a new skill
Create `skills/<skill_name>/` with:
- `SKILL.md`
- `run.py` (or another entry)

## Add dependencies
- **Python deps:** edit `sandbox/requirements.txt`, then `make build`
- **OS deps:** edit `Dockerfile` (apt-get), then `make build`

Commit changes so everyone stays consistent.