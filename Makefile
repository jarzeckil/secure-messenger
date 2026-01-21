.PHONY: install format lint test init

PROJECT_NAME = secure-messenger
PYTHON_VERSION = 3.13
PYTHON_INTERPRETER = python

help:
	@grep -E '\s##\s' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'

install: ## install dependencies
	poetry install
	poetry run pre-commit install

format: ## auto format files
	poetry run ruff format .
	poetry run ruff check . --fix

lint: ## check formating
	poetry run ruff check .
	poetry run ruff format --check

test: ## run tests
	poetry run pytest tests/

init: ## create poetry environment
	poetry env use $(PYTHON_VERSION)
	@echo ">>> Poetry environment created."

clean: ## Delete all compiled Python files
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name ".ruff_cache" -delete
