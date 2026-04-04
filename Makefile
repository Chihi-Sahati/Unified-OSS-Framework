# Unified OSS Framework - Makefile
# Build, test, and deployment automation

.PHONY: help install dev test lint format clean docker-build docker-up docker-down docs

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := pip3
DOCKER := docker
DOCKER_COMPOSE := docker-compose

# Colors
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
RESET := \033[0m

help: ## Show this help message
	@echo "$(GREEN)Unified OSS Framework - Available Commands:$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(RESET) %s\n", $$1, $$2}'

# Installation
install: ## Install production dependencies
	$(PIP) install -r requirements.txt

install-dev: ## Install development dependencies
	$(PIP) install -r requirements-dev.txt

# Testing
test: ## Run all tests
	$(PYTHON) -m pytest tests/ -v --cov=src/unified_oss --cov-report=term-missing

test-unit: ## Run unit tests only
	$(PYTHON) -m pytest tests/unit/ -v

test-integration: ## Run integration tests only
	$(PYTHON) -m pytest tests/integration/ -v

test-coverage: ## Run tests with HTML coverage report
	$(PYTHON) -m pytest tests/ -v --cov=src/unified_oss --cov-report=html
	@echo "$(GREEN)Coverage report generated: htmlcov/index.html$(RESET)"

# Code Quality
lint: ## Run all linting tools
	$(PYTHON) -m flake8 src/ tests/
	$(PYTHON) -m pylint src/ --exit-zero
	$(PYTHON) -m mypy src/ --ignore-missing-imports

format: ## Format code with black and isort
	$(PYTHON) -m black src/ tests/
	$(PYTHON) -m isort src/ tests/

format-check: ## Check code formatting
	$(PYTHON) -m black --check src/ tests/
	$(PYTHON) -m isort --check-only src/ tests/

security: ## Run security checks
	$(PYTHON) -m bandit -r src/
	$(PYTHON) -m safety check

# YANG Validation
yang-validate: ## Validate all YANG modules
	@echo "$(GREEN)Validating YANG modules...$(RESET)"
	@for f in yang-modules/*.yang; do \
		echo "Validating $$f..."; \
		pyang --strict --lint $$f || true; \
	done

yang-tree: ## Generate YANG tree diagrams
	@mkdir -p yang-modules/tree
	@for f in yang-modules/*.yang; do \
		echo "Generating tree for $$f..."; \
		pyang -f tree $$f > yang-modules/tree/$$(basename $$f .yang).tree || true; \
	done

# Database
db-init: ## Initialize database schema
	$(PYTHON) -c "from unified_oss.database import init_database; init_database()"

db-migrate: ## Run database migrations
	@echo "$(GREEN)Running database migrations...$(RESET)"
	@for f in sql-migrations/*.sql; do \
		echo "Applying $$f..."; \
		PGPASSWORD=postgres psql -h localhost -U postgres -d unified_oss -f $$f || true; \
	done

# Docker
docker-build: ## Build Docker image
	$(DOCKER) build -t unified-oss-framework:latest .

docker-up: ## Start all services with Docker Compose
	$(DOCKER_COMPOSE) up -d

docker-down: ## Stop all Docker services
	$(DOCKER_COMPOSE) down

docker-logs: ## View Docker logs
	$(DOCKER_COMPOSE) logs -f unified-oss

docker-clean: ## Remove all Docker containers and volumes
	$(DOCKER_COMPOSE) down -v --remove-orphans

# Documentation
docs: ## Build documentation
	cd docs && $(PYTHON) -m sphinx -b html . _build/html

docs-serve: ## Serve documentation locally
	cd docs && $(PYTHON) -m sphinx -b html . _build/html && \
	$(PYTHON) -m http.server 8000 -d docs/_build/html

# Development
dev: ## Start development server
	$(PYTHON) -m uvicorn unified_oss.api.rest.app:app --reload --host 0.0.0.0 --port 8080

# Cleanup
clean: ## Clean generated files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name ".coverage" -delete
	@echo "$(GREEN)Cleaned generated files$(RESET)"

# All checks
check: format-check lint test yang-validate ## Run all checks (format, lint, test, yang)

# CI pipeline locally
ci: install-dev format-check lint test security yang-validate ## Run CI pipeline locally
