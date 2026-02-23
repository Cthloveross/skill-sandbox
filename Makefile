build:
	docker compose build

run:
	docker compose run --rm sandbox --skill $(SKILL) --entry $(ENTRY) -- $(ARGS)

shell:
	docker compose run --rm sandbox bash
