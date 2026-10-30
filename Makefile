PROJ_NAME = $(shell grep -m1 -oP 'name\s*=\s*"\K[^"]+' pyproject.toml)
PROJ_VERSION := $(shell grep -m1 -oP 'version\s*=\s*"\K[^"]+' pyproject.toml)


.PHONY: clean
clean:
	# Clean up cached files and build artefacts
	find ${PROJ_NAME} tests -type f -name "*.pyc" -delete
	find ${PROJ_NAME} tests -type d -name "__pycache__" -delete
	rm -rf ${PROJ_NAME}.egg-info dist

.PHONY: venv
venv:
	@test -d .venv || python -m venv .venv


.PHONY: install
install: venv
	# Install dependencies
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

.PHONY: install-dev
install-dev: install
	# Install dev dependencies 
	.venv/bin/pip install pip-tools pytest build bump twine

.PHONY: compile
compile:
	# Compile requirements from pyproject.toml
	.venv/bin/python -m piptools compile --upgrade --strip-extras


.PHONY: test
test:
	# Run all tests
	.venv/bin/python -m pytest


.PHONY: bump bump-patch bump-minor bump-major
bump: NEW_VERSION = $(shell .venv/bin/python -m bump --patch)
bump-patch: NEW_VERSION = $(shell .venv/bin/python -m bump --patch)
bump-minor: NEW_VERSION = $(shell .venv/bin/python -m bump --reset --minor)
bump-major: NEW_VERSION = $(shell .venv/bin/python -m bump --reset --major)

bump bump-patch bump-minor bump-major:
	@new_version=${NEW_VERSION}; \
	echo "Updating from ${PROJ_VERSION} to $$new_version ..."; \
	git add pyproject.toml; \
	git commit -m "chore: bump version from ${PROJ_VERSION} to $$new_version"


.PHONY: build
build:
ifeq ($(shell find dist -type f -name "${PROJ_NAME}-${PROJ_VERSION}*"),)
	.venv/bin/python -m build
	@echo "Built ${PROJ_NAME} version ${PROJ_VERSION}..."
else
	@echo "Version ${PROJ_VERSION} build exists!"
endif

.PHONY: release
release: build
	.venv/bin/python -m twine upload --skip-existing --repository pypi dist/${PROJ_NAME}-${PROJ_VERSION}*
