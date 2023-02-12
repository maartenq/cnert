# Makefile

.DEFAULT_GOAL := help
define BROWSER_PYSCRIPT
import os, webbrowser, sys
try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT
BROWSER := python -c "$$BROWSER_PYSCRIPT"

PACKAGE = cnert

.PHONY: help
help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

.PHONY: lint
lint: ## Run all pre-commit hooks on all files
	pre-commit run --all-files --show-diff-on-failure

.PHONY: test
test: ## Run tests quickly with the default Python.
	python -m pytest --cov=$(PACKAGE)

.PHONY: coverage
coverage: ## Check code coverage quickly with the default Python.
	python -m coverage erase
	python -m coverage run --source $(PACKAGE) -m pytest
	python -m coverage report -m
	python -m coverage html
	$(BROWSER) htmlcov/index.html

.PHONY: tox
tox: ## Run tests on every Python version with tox.
	tox

.PHONY: docs
docs: clean-docs ## Generate MkDocs HTML documentation
	mkdocs build
	$(BROWSER) site/index.html

.PHONY: clean
clean: clean-git clean-build clean-pyc clean-test clean-docs ## Clean all

.PHONY: clean-git
clean-git: ## Remove untracked files from the working tree (using `git clean`)
	git clean --force -x -d

.PHONY: clean-build
clean-build: ## Remove build artifacts.
	rm -rf build/
	rm -rf dist/
	rm -rf .eggs/
	find . -name '*.egg-info' -exec rm -rf {} +
	find . -name '*.egg' -exec rm -f {} +

.PHONY: clean-pyc
clean-pyc: ## Remove Python file artifacts.
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +

.PHONY: clean-test
clean-test: ## Remove test and coverage artifacts.
	rm -f .coverage
	rm -f coverage.xml
	rm -rf .pytest_cache
	rm -rf .tox/
	rm -f .coverage
	rm -rf htmlcov/

.PHONY: clean-docs
clean-docs: ## Remove MkDocs site/ directory
	rm -rf site/
