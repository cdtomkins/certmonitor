# Makefile for certmonitor project

.PHONY: develop build wheel test docs clean lint format verify-wheel

# Install the package in development mode (Python + Rust)
develop:
	uv pip install -e .
	uv run maturin develop

# Build the wheel (Python + Rust)
wheel:
	uv run maturin build --release

# Full build
build: develop

# Run tests
test:
	uv pip install -e .
	uv run pytest -v

# Serve documentation
docs:
	uv run mkdocs serve

# Lint code
lint:
	uv run ruff check .

# Format code
format:
	uv run ruff format .

# Clean all build artifacts, cache, eggs, and venv
clean:
	rm -rf \
		build/ \
		dist/ \
		target/ \
		.mypy_cache/ \
		.pytest_cache/ \
		.venv/ \
		certmonitor.egg-info/ \
		__pycache__/ \
		**/__pycache__/ \
		*.egg-info \
		*.pyc \
		*.pyo \
		*.pyd \
		*.log \
		.DS_Store \
		*.so \
		*.c \
		*.o \
		*.rlib \
		*.rmeta \
		*.dll \
		*.dylib \
		*.exe \
		*.a \
		*.out

# Verify the contents of the built wheel
verify-wheel:
	@echo "🔍 Verifying wheel contents..."
	unzip -l target/wheels/certmonitor-*.whl | grep certmonitor