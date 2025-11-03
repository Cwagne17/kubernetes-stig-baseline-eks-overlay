.PHONY: help test check validate lint install

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies (cinc-auditor)
	@echo "Checking for cinc-auditor installation..."
	@command -v cinc-auditor >/dev/null 2>&1 || { echo >&2 "cinc-auditor is not installed. Please install it: https://cinc.sh/start/auditor/"; exit 1; }
	@echo "cinc-auditor is installed: $$(cinc-auditor --version)"

install-ssm: ## Install train-awsssm plugin for SSM Session Manager transport
	@echo "Installing train-awsssm plugin..."
	cinc-auditor plugin install train-awsssm
	@echo "Plugin installed successfully"

check: install ## Run profile check (validate syntax)
	@echo "Checking profile syntax..."
	cinc-auditor check .

test: install ## Run profile tests (execute controls)
	@echo "Running profile tests..."
	@mkdir -p output
	cinc-auditor exec . --reporter cli json:output/results.json

validate: check ## Alias for check

lint: check ## Alias for check

clean: ## Remove test results
	@echo "Cleaning up test results..."
	rm -rf output

info: install ## Show profile information
	@echo "Profile information:"
	cinc-auditor json . | jq -r '.name, .title, .version'

serve: ## Start Heimdall Lite to view results (requires Docker)
	@echo "Starting Heimdall Lite..."
	docker compose up -d
	@echo ""
	@echo "✅ Heimdall Lite is running at http://localhost:8080"
	@echo "   Upload output/results.json to view your test results"

stop: ## Stop Heimdall Lite
	@echo "Stopping Heimdall Lite..."
	docker compose down
