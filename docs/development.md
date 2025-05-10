# Development Guide

This project uses a combination of Python and Rust to provide robust, high-performance certificate parsing and validation. Below you'll find instructions for setting up your development environment, running tests, and understanding why Rust is used for part of the codebase.

## Setting Up Your Environment

1. **Install Python (3.8–3.13 recommended)**
2. **Install [uv](https://github.com/astral-sh/uv) for fast dependency management:**
   - Official install (recommended, from the [uv docs](https://github.com/astral-sh/uv#installation)):
     ```sh
     curl -Ls https://astral.sh/uv/install.sh | sh
     ```
3. **Install Rust (for the Rust extension):**
   - [Install Rust](https://www.rust-lang.org/tools/install) (includes `cargo`)
4. **Install maturin (for building the Rust extension):**
   ```sh
   uv sync --group dev
   ```
5. **Install all Python dev dependencies:**
   ```sh
   uv sync --group dev
   ```
6. **Build the Rust extension:**
   ```sh
   make maturin-develop
   ```
   Or, for a full build (Python + Rust):
   ```sh
   make build
   ```

## Running Tests

```sh
make test
```

## Running the Docs

```sh
make docs
```

## Why Rust for Certificate Parsing?

Parsing X.509 certificates and extracting cryptographic key information is performance-critical and security-sensitive. Python's standard library does not provide low-level, robust, or fast parsing for all certificate fields, especially for public key extraction and ASN.1 parsing. Rust, with its strong safety guarantees and excellent cryptography ecosystem, is ideal for this task.

- **Performance:** Rust code is compiled and runs much faster than pure Python for binary parsing.
- **Safety:** Rust's memory safety model helps prevent many classes of bugs and vulnerabilities.
- **Ecosystem:** The Rust `x509-parser` crate is mature and reliable for certificate parsing.

The Rust extension is built as a Python module using [PyO3](https://pyo3.rs/) and [maturin](https://github.com/PyO3/maturin), and is automatically installed as part of the development workflow.

## Typical Workflow

- Edit Python or Rust code as needed.
- Rebuild the Rust extension if you change Rust code:
  ```sh
  make maturin-develop
  ```
- Run tests and docs as above.

---

For more details, see the Makefile and `pyproject.toml` for up-to-date commands and dependencies.
