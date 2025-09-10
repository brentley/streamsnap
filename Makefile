.PHONY: help up test build deploy logs shell stop clean status

help:
	@echo "StreamSnap - Available commands:"
	@echo "  make up      - Start StreamSnap (production-ready)"
	@echo "  make test    - Run tests"
	@echo "  make build   - Build Docker image"
	@echo "  make deploy  - Deploy to production"
	@echo "  make logs    - View logs"
	@echo "  make shell   - Access container shell"
	@echo "  make stop    - Stop all containers"
	@echo "  make clean   - Clean up everything"
	@echo "  make status  - Show container status"

up:
	@echo "Starting StreamSnap..."
	docker compose up -d

test:
	@echo "Running StreamSnap tests..."
	docker compose run --rm streamsnap python -m pytest tests/ -v

build:
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

status:
	@echo "StreamSnap container status:"
	@docker compose ps