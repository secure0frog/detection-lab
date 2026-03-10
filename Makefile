.PHONY: help up down init scan-files scan-logs scan-all layers layers-group status clean full-demo

COMPOSE = docker compose
DETTECT_EXEC = docker exec dettect

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

up: ## Start all services (OpenSearch, Dashboards, DeTTECT, YARA scanner)
	$(COMPOSE) up -d --build

down: ## Stop all services
	$(COMPOSE) down

init: ## First-time setup: download samples + load data into OpenSearch
	bash scripts/download-samples.sh
	$(COMPOSE) --profile init run --rm data-loader

scan-files: ## Run YARA file scan against samples
	@echo "=== YARA File Scan ==="
	@curl -sf -X POST http://localhost:8081/scan/files | python3 -m json.tool

scan-logs: ## Run YARA log scan against event data
	@echo "=== YARA Log Scan ==="
	@curl -sf -X POST http://localhost:8081/scan/logs | python3 -m json.tool

scan-all: ## Run both file and log YARA scans
	$(MAKE) scan-files
	@echo ""
	$(MAKE) scan-logs

layers: ## Generate ATT&CK Navigator layers via DeTTECT
	@echo "=== Generating Visibility Layer ==="
	$(DETTECT_EXEC) python dettect.py v \
		-ft /opt/DeTTECT/input/techniques-administration-endpoints.yaml -l
	@echo "=== Generating Detection Layer ==="
	$(DETTECT_EXEC) python dettect.py d \
		-ft /opt/DeTTECT/input/techniques-administration-endpoints.yaml -l
	@echo "=== Layers generated in dettect/output/ ==="

layers-group: ## Generate group overlay layer
	$(DETTECT_EXEC) python dettect.py g \
		-g /opt/DeTTECT/input/groups.yaml \
		-o /opt/DeTTECT/input/techniques-administration-endpoints.yaml \
		-t detection

status: ## Check service health
	@$(COMPOSE) ps
	@echo ""
	@echo "--- OpenSearch ---"
	@curl -sf http://localhost:9200/_cluster/health 2>/dev/null | python3 -m json.tool || echo "  Not ready"
	@echo ""
	@echo "--- YARA Scanner ---"
	@curl -sf http://localhost:8081/health 2>/dev/null | python3 -m json.tool || echo "  Not ready"

clean: ## Remove all containers, volumes, and generated data
	$(COMPOSE) down -v
	rm -rf dettect/output/*.json dettect/output/*.xlsx

full-demo: ## Complete demo: start -> init -> scan -> generate layers
	@echo "=== Starting all services ==="
	$(MAKE) up
	@echo "=== Waiting for services to be healthy ==="
	@for i in $$(seq 1 60); do \
		if curl -sf http://localhost:9200/_cluster/health >/dev/null 2>&1 && \
		   curl -sf http://localhost:8081/health >/dev/null 2>&1; then \
			echo "  Services ready!"; \
			break; \
		fi; \
		echo "  Waiting... ($$i/60)"; \
		sleep 5; \
	done
	@echo ""
	@echo "=== Loading sample data ==="
	$(MAKE) init
	@echo ""
	@echo "=== Running YARA scans ==="
	$(MAKE) scan-all
	@echo ""
	@echo "=== Generating ATT&CK Navigator layers ==="
	$(MAKE) layers
	@echo ""
	@echo "=========================================="
	@echo "  Detection Lab Ready!"
	@echo "=========================================="
	@echo "  OpenSearch Dashboards: http://localhost:5601"
	@echo "  DeTTECT Editor:       http://localhost:8080"
	@echo "  YARA Scanner API:     http://localhost:8081"
	@echo "  Navigator layers:     ./dettect/output/"
	@echo "=========================================="
