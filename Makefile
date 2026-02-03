.PHONY: help sync install init-db run rundev check clean

SHELL := /bin/bash
VENV_DIR := .venv_docker
PYTHON := $(VENV_DIR)/bin/python
FLASK := $(VENV_DIR)/bin/flask
RUFF := $(VENV_DIR)/bin/ruff
TY := $(VENV_DIR)/bin/ty

help:
	@echo "Gatekeeper - Authentication Service"
	@echo "------------------------------------"
	@echo "sync     - Sync dependencies with uv (creates venv if needed)"
	@echo "install  - Alias for sync"
	@echo "init-db  - Create a blank database"
	@echo "run      - Run server with production settings (HOST:PORT)"
	@echo "rundev   - Run server with dev settings (DEV_HOST:DEV_PORT, debug=True)"
	@echo "check    - Run ruff and ty for code quality"
	@echo "clean    - Remove temporary files and database"

sync:
	@uv sync --extra dev

install: sync

init-db:
	@$(FLASK) --app wsgi init-db

run:
	@$(PYTHON) wsgi.py

rundev:
	@$(PYTHON) wsgi.py --dev

check:
	@$(RUFF) format src
	@$(RUFF) check src --fix
	@$(TY) check src

clean:
	@find . -type f -name '*.py[co]' -delete
	@find . -type d -name '__pycache__' -delete
	@rm -f instance/gatekeeper.sqlite3
