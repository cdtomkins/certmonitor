# Development Guide

This guide is for contributors and advanced users who want to build CertMonitor from source, work on the codebase, or use the Rust-powered features in development.

## Local Development Setup

1. **Clone the repository:**
    ```sh
    git clone <repo-url>
    cd certmonitor
    ```
2. **Install dev dependencies (includes maturin):**

    === "uv"
        ```sh
        uv sync --group dev
        ```

    === "pip"
        ```sh
        pip install -e .[dev]
        ```

3. **Install Rust toolchain:**
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    # Or see https://www.rust-lang.org/tools/install
    ```
4. **Build and install the Rust bindings:**
    ```sh
    make maturin-develop
    ```

---

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
