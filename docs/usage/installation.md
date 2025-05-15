# Installation

You can install CertMonitor using your preferred Python package manager. Below are examples for both pip and uv:

=== "pip"
    ```sh
    pip install certmonitor
    ```

=== "uv"
    ```sh
    uv add certmonitor
    ```

---

> **Note:** If you want to install CertMonitor for development, build from source, or work with Rust bindings, see the [Development Guide](../development.md) for full instructions.

---

## Supported Python Versions

- Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13

---

> **Note:** If you are installing CertMonitor from PyPI using pip or uv, you do not need Rust or OpenSSL installed. Pre-built wheels are provided for all major platforms and Python versions. System dependencies are only required if you are building from source or developing CertMonitor itself. See the [Development Guide](../development.md) for details.

---

## Rust Toolchain (Required for Advanced Features)

CertMonitor uses Rust bindings for fast, safe certificate parsing and public key extraction. **Rust is required for advanced public key and elliptic curve features, but all orchestration and logic are pure Python stdlib.** If you want to build from source or contribute, install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
