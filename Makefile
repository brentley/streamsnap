.PHONY: help dev prod test build deploy logs shell stop clean health

help:
	@echo "StreamSnap - Available commands:"
	@echo "  make dev     - Start development environment"
	@echo "  make prod    - Start production environment"
	@echo "  make test    - Run tests"
	@echo "  make build   - Build Docker image"
	@echo "  make deploy  - Deploy to production"
	@echo "  make logs    - View logs"
	@echo "  make shell   - Access container shell"
	@echo "  make stop    - Stop all containers"
	@echo "  make clean   - Clean up everything"
	@echo "  make health  - Check service health"

dev:
	@echo "Starting StreamSnap development environment..."
	docker compose -f docker-compose.dev.yml up --build

prod:
	@echo "Starting StreamSnap production environment..."
	docker compose up -d

test:
	@echo "Running StreamSnap tests..."
	@if [ -d tests ] || ls test_*.py 1> /dev/null 2>&1; then \
		docker compose -f docker-compose.dev.yml run --rm streamsnap-dev python -m pytest tests/ -v || \
		docker compose -f docker-compose.dev.yml run --rm streamsnap-dev python -m pytest test_*.py -v; \
	else \
		echo "Running basic import test..."; \
		docker compose -f docker-compose.dev.yml run --rm streamsnap-dev python -c "import streamsnap_app; print('✅ Application imports successfully')"; \
	fi

build:
	@echo "Generating version information..."
	@mkdir -p scripts
	@chmod +x scripts/generate-version.sh
	@./scripts/generate-version.sh
	@echo "Building StreamSnap Docker image..."
	docker compose build

deploy:
	@echo "StreamSnap deployment is automated via GitHub Actions"
	@echo "Push to main branch to trigger deployment"
	@echo "Current containers will be updated automatically by Watchtower"

logs:
	@echo "Viewing StreamSnap logs..."
	docker compose logs -f

shell:
	@echo "Accessing StreamSnap container shell..."
	docker compose exec streamsnap /bin/bash

stop:
	@echo "Stopping StreamSnap containers..."
	docker compose down

clean:
	@echo "Cleaning up StreamSnap containers and volumes..."
	docker compose down -v
	docker system prune -f

health:
	@echo "Checking StreamSnap health..."
	@curl -f http://localhost:5000/health 2>/dev/null && echo "\n✅ StreamSnap is healthy" || echo "❌ StreamSnap health check failed"