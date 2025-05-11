# Makefile for certmonitor project

.PHONY: maturin-develop build maturin-build test docs

maturin-develop:
	uv run maturin develop --manifest-path certmonitor/rust_certinfo/Cargo.toml

build:
	uv pip install -e .
	$(MAKE) maturin-develop

maturin-build:
	uv run maturin build --release --manifest-path certmonitor/rust_certinfo/Cargo.toml

test:
	uv pip install -e .
	pytest -v

docs:
	mkdocs serve
