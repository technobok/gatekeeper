.PHONY: help sync install init-db run rundev check clean

SHELL := /bin/bash
VENV_DIR := $(or $(VIRTUAL_ENV),.venv)
PYTHON := $(VENV_DIR)/bin/python
FLASK := $(VENV_DIR)/bin/flask
GUNICORN := $(VENV_DIR)/bin/gunicorn
RUFF := $(VENV_DIR)/bin/ruff
TY := $(VENV_DIR)/bin/ty

help:
	@echo "Gatekeeper - Authentication Service"
	@echo "------------------------------------"
	@echo "sync     - Sync dependencies with uv (creates venv if needed)"
	@echo "install  - Alias for sync"
	@echo "init-db  - Create a blank database"
	@echo "run      - Run server via gunicorn (0.0.0.0:5100)"
	@echo "rundev   - Run Flask dev server (DEV_HOST:DEV_PORT, debug=True)"
	@echo "check    - Run ruff and ty for code quality"
	@echo "clean    - Remove temporary files and database"

sync:
	@uv sync --extra dev

install: sync

init-db:
	@$(FLASK) --app wsgi init-db

run:
	@$(GUNICORN) wsgi:app --bind 0.0.0.0:5100 --workers 2 --preload

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
