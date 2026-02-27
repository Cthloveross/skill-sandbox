.DEFAULT_GOAL := help
SKILL  ?= _template
ENTRY  ?= run.py
ARGS   ?=

# ── Core commands ──────────────────────────────
build:  ## Build (or rebuild) the sandbox Docker image
	docker compose build

run:    ## Run a skill  →  make run SKILL=pdf ENTRY=scripts/check_fillable_fields.py ARGS="file.pdf"
	docker compose run --rm sandbox --skill $(SKILL) --entry $(ENTRY) -- $(ARGS)

run-net:  ## Run a skill WITH network access (mcp-builder, web-artifacts-builder, webapp-testing)
	docker compose run --rm -e NETWORK=1 --network=default sandbox --skill $(SKILL) --entry $(ENTRY) -- $(ARGS)

shell:  ## Open a bash shell inside the sandbox
	docker compose run --rm --entrypoint bash sandbox

shell-net:  ## Open a bash shell WITH network access
	docker compose run --rm --entrypoint bash --network=default sandbox

# ── Verification ───────────────────────────────
verify:  ## Verify a skill for malicious behavior  →  make verify SKILL=docx-to-pdf
	docker compose run --rm --entrypoint python sandbox -m verifier.scan_skill --skill $(SKILL)

verify-all:  ## Verify ALL skills for malicious behavior
	docker compose run --rm --entrypoint python sandbox -m verifier.scan_skill --all

# ── Utilities ──────────────────────────────────
list:   ## List all available skills
	@echo "Available skills:" && echo "─────────────────" && ls -1 skills/ | grep -v '^_'

clean:  ## Remove stopped containers and dangling images
	docker compose down --remove-orphans
	docker image prune -f

help:   ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
