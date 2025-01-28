.PHONY: install
install: ## Install the poetry environment and install the pre-commit hooks
	@echo "🚀 Creating virtual environment using pyenv and poetry"
	@poetry install
	@poetry run pre-commit install
	@poetry shell

docs/requirements.txt: poetry.lock
	@echo "🚀 Create or update docs/requirements.txt"
	@poetry export --with=docs --without-hashes --output=docs/requirements.txt

poetry.lock: pyproject.toml
	@echo "🚀 Create or update poetry.lock"
	@poetry update

.PHONY: update
update: docs/requirements.txt ## Update the dependencies as according to the pyproject.toml file

.PHONY: check
check: ## Run code quality tools.
	@echo "🚀 Checking Poetry lock file consistency with 'pyproject.toml': Running poetry lock --check"
	@poetry check --lock
	@echo "🚀 Linting code: Running pre-commit"
	@poetry run pre-commit run -a
	@echo "🚀 Static type checking: Running mypy"
	@poetry run mypy src/

.PHONY: test
test: ## Test the code with pytest
	@echo "🚀 Testing code: Running pytest"
	@poetry run pytest --verbose --cov --cov-config=pyproject.toml --cov-report=xml

.PHONY: htmlcov
htmlcov: ## Create HTML coverage report
	@echo "🚀 Create HTML coverage report"
	@poetry run coverage html

.PHONY: cov
cov: test htmlcov ## Test, make coverage html and open
	@echo "🚀 Openeing coverage report"
	open htmlcov/index.html

.PHONY: build
build: clean-build ## Build wheel file using poetry
	@echo "🚀 Creating wheel file"
	@poetry build

.PHONY: clean-build
clean-build: ## clean build artifacts
	@rm -rf dist

.PHONY: publish
publish: ## publish a release to pypi.
	@echo "🚀 Publishing: Dry run."
	@poetry config pypi-token.pypi $(PYPI_TOKEN)
	@poetry publish --dry-run
	@echo "🚀 Publishing."
	@poetry publish

.PHONY: build-and-publish
build-and-publish: build publish ## Build and publish.

.PHONY: docs-test
docs-test: ## Test if documentation can be built without warnings or errors
	@poetry run mkdocs build -s

.PHONY: docs
docs: ## Build and serve the documentation
	@poetry run mkdocs serve

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "🔸 \033[36m%-20s\033[0m ▫️  %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
