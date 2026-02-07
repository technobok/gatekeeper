.PHONY: help sync install init-db import-users bootstrap-key run rundev check clean config-list config-set config-import config-export

SHELL := /bin/bash
VENV_DIR := $(or $(VIRTUAL_ENV),.venv)
ADMIN := $(VENV_DIR)/bin/gatekeeper-admin
WEB := $(VENV_DIR)/bin/gatekeeper-web
GUNICORN := $(VENV_DIR)/bin/gunicorn
RUFF := $(VENV_DIR)/bin/ruff
TY := $(VENV_DIR)/bin/ty

help:
	@echo "Gatekeeper - Authentication Service"
	@echo "------------------------------------"
	@echo "sync     - Sync dependencies with uv (creates venv if needed)"
	@echo "install  - Alias for sync"
	@echo "init-db  - Create a blank database"
	@echo "import-users FILE=path/to/users.csv"
	@echo "           - Import users from CSV (columns: username,email,fullname)"
	@echo "bootstrap-key [DESC=description]"
	@echo "           - Generate an API key for service bootstrap (prints to console)"
	@echo "run      - Run server via gunicorn (0.0.0.0:5100)"
	@echo "rundev   - Run Flask dev server (DEV_HOST:DEV_PORT, debug=True)"
	@echo "config-list  - Show all config settings"
	@echo "config-set KEY=key VAL=value  - Set a config value"
	@echo "config-import FILE=path  - Import settings from INI file"
	@echo "config-export FILE=path  - Export all settings as a shell script"
	@echo "check    - Run ruff and ty for code quality"
	@echo "clean    - Remove temporary files and database"
	@echo ""
	@echo "Database: instance/gatekeeper.sqlite3 (default)"
	@echo "Set GATEKEEPER_DB to override, e.g.:"
	@echo "  export GATEKEEPER_DB=/data/gatekeeper.sqlite3"

sync:
	@uv sync --extra dev

install: sync

init-db:
	@$(ADMIN) init-db

import-users:
	@$(ADMIN) import-users $(or $(FILE),$(file))

bootstrap-key:
	@$(ADMIN) generate-api-key --description "$(or $(DESC),bootstrap)"

run:
	@$(GUNICORN) wsgi:app --bind 0.0.0.0:5100 --workers 2 --preload

rundev:
	@$(WEB) --dev

config-list:
	@$(ADMIN) config list

config-set:
	@$(ADMIN) config set $(KEY) '$(VAL)'

config-import:
	@$(ADMIN) config import $(or $(FILE),$(file))

config-export:
	@$(ADMIN) config export $(or $(FILE),$(file))

check:
	@$(RUFF) format src
	@$(RUFF) check src --fix
	@if [ -z "$$VIRTUAL_ENV" ]; then unset VIRTUAL_ENV; fi; $(TY) check src

clean:
	@find . -type f -name '*.py[co]' -delete
	@find . -type d -name '__pycache__' -delete
	@rm -f instance/gatekeeper.sqlite3
