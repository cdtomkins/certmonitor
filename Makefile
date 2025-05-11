# Makefile for certmonitor project

.PHONY: maturin-develop build maturin-build test docs clean lint format

# Develop using maturin
maturin-develop:
	uv run maturin develop --manifest-path certmonitor/rust_certinfo/Cargo.toml

# Build the project
build:
	uv pip install -e .
	$(MAKE) maturin-develop

# Build using maturin
maturin-build:
	uv run maturin build --release --manifest-path certmonitor/rust_certinfo/Cargo.toml

# Run tests
test:
	uv pip install -e .
	pytest -v

# Serve documentation
docs:
	mkdocs serve

# Clean build artifacts and caches
clean:
	rm -rf build/ dist/ .venv/ .mypy_cache/ .pytest_cache/ __pycache__ */__pycache__ *.egg-info

# Lint code using ruff
lint:
	uv run ruff check .

# Format code using ruff
format:
	uv run ruff format .
