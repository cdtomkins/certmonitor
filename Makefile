# Makefile for certmonitor project

.PHONY: maturin-develop build test docs

maturin-develop:
	cd certmonitor/rust_certinfo && maturin develop

build:
	uv pip install -e .
	$(MAKE) maturin-develop

test:
	uv pip install -e .
	pytest

docs:
	mkdocs serve
