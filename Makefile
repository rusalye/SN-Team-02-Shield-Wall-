COMPOSE = docker compose
SENTINEL = http://127.0.0.1:9000

.PHONY: certs up down clean mode-on mode-detect mode-off benign attack demo report unban fp logs test

certs:
	./scripts/gen_certs.sh

up: certs
	$(COMPOSE) up -d --build
	@echo "App via WAF: https://localhost:8443   Dashboard: $(SENTINEL)   Attack Console: http://127.0.0.1:8501"

down:
	$(COMPOSE) --profile lab down

clean:
	$(COMPOSE) --profile lab down -v --remove-orphans
	rm -f reports/*.json reports/*.md

mode-on:
	./scripts/set_mode.sh on
mode-detect:
	./scripts/set_mode.sh detect
mode-off:
	./scripts/set_mode.sh off

benign:
	$(COMPOSE) run --rm client python benign_replay.py --label benign

attack:
	$(COMPOSE) run --rm attacker python attack_replay.py --expect block --label attack

demo: certs
	./scripts/demo.sh

report:
	curl -fs $(SENTINEL)/report.md -o reports/alert_summary.md && echo reports/alert_summary.md
	curl -fs $(SENTINEL)/api/navigator-layer -o reports/attack_navigator_layer.json

unban:
	curl -fs -X POST -d '{"all":true}' $(SENTINEL)/api/unban

fp:
	@curl -fs "$(SENTINEL)/api/events?ip=172.28.0.101&blocked=1&limit=20" | python3 -m json.tool

test:
	cd sentinel && python3 -m unittest discover -s tests -v
	cd console && python3 -m unittest discover -s tests -v

logs:
	$(COMPOSE) logs -f waf sentinel
