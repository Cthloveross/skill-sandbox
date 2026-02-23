# Contributing Skills (teammates-only)

## Skill contract
Each skill lives in `skills/<name>/` and must include:
- `SKILL.md` (what it does + how to run)
- `run.py` (default entry)

## Dependency rules
1) If only ONE skill needs a dependency, still add it to:
   - `sandbox/requirements.txt` (Python), or
   - `Dockerfile` (system packages)
   so the sandbox stays reproducible for everyone.

2) After editing deps:
   - run `make build`
   - run the skill locally
   - commit both skill + env changes in the same PR

## Network policy
Default container has no network. If your skill needs network:
- Document it in `SKILL.md`
- Temporarily disable `network_mode: "none"` during development if necessary
