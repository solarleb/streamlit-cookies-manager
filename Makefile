# Get the version from Poetry
version = $(shell poetry version -s)

# All Python source files that should trigger a rebuild
python_sources = $(wildcard streamlit_cookies_manager/*.py) pyproject.toml MANIFEST.in

# All JavaScript/TypeScript source files that should trigger a frontend build
# Using **/* for a more robust recursive glob pattern
js_sources := $(wildcard streamlit_cookies_manager/public/**/*) \
              $(wildcard streamlit_cookies_manager/src/**/*) \
              streamlit_cookies_manager/index.html \
              streamlit_cookies_manager/vite.config.ts \
              streamlit_cookies_manager/tsconfig.json \
              streamlit_cookies_manager/package.json \
              streamlit_cookies_manager/package-lock.json

# A marker file to check if `npm install` has been run.
# Using .npm-install-done as a more explicit marker.
npm_install_marker = streamlit_cookies_manager/.npm-install-done

# Main build target, depends on the frontend build and package builds
.PHONY: build sdist wheels js clean

build: js sdist wheels

# Phony targets to explicitly build sdist and wheels
sdist: dist/streamlit-cookies-manager-$(version).tar.gz
wheels: dist/streamlit_cookies_manager-$(version)-py3-none-any.whl

# This target ensures the frontend is built.
js: streamlit_cookies_manager/build/index.html

# Rule to build the sdist. Depends on Python sources and the 'js' target.
dist/streamlit-cookies-manager-$(version).tar.gz: $(python_sources) js
	poetry build -f sdist

# Rule to build the wheel. Depends on Python sources and the 'js' target.
dist/streamlit_cookies_manager-$(version)-py3-none-any.whl: $(python_sources) js
	poetry build -f wheel

# Rule to build the frontend component using npm.
streamlit_cookies_manager/build/index.html: $(js_sources) $(npm_install_marker)
	@echo "--- Building frontend component ---"
	cd streamlit_cookies_manager && npm run build

# Rule to install npm dependencies. Creates a marker file upon success.
$(npm_install_marker): streamlit_cookies_manager/package.json streamlit_cookies_manager/package-lock.json
	@echo "--- Installing npm dependencies ---"
	cd streamlit_cookies_manager && npm install
	@touch $@ # Create the marker file after successful install

clean:
	@echo "--- Cleaning build artifacts ---"
	-rm -rf dist/*
	-rm -rf streamlit_cookies_manager/build/*
	-rm -rf streamlit_cookies_manager/.npm-install-done
	-find . -name "__pycache__" -type d -exec rm -rf {} +
	-find . -name "*.egg-info" -type d -exec rm -rf {} +

.PHONY: format lint typecheck pre-commit-install

format:
	poetry run black .

lint:
	poetry run ruff check . --fix

typecheck:
	poetry run mypy --config-file=pyproject.toml streamlit_cookies_manager

pre-commit-install:
	poetry run pre-commit install
