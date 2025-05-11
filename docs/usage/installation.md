# Installation

CertMonitor supports Python 3.8–3.13 and requires a modern pip, uv, or poetry environment. It is cross-platform and works on Linux, macOS, and Windows (with OpenSSL support).

## Install from PyPI

```bash
pip install certmonitor
```

## Install with uv (recommended for speed)

```bash
uv pip install certmonitor
```

## Install with Poetry

```bash
poetry add certmonitor
```

## Supported Python Versions

- Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13

## Rust Toolchain (Required for Advanced Features)

CertMonitor uses Rust bindings for fast, safe certificate parsing and public key extraction. **Rust is required for advanced public key and elliptic curve features, but all orchestration and logic are pure Python stdlib.** If you want to build from source or contribute, install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Troubleshooting Installation

- If you see errors about maturin, Rust, or OpenSSL, ensure you have a working Rust toolchain and OpenSSL headers installed. **Most CertMonitor features use only the Python standard library, but advanced cryptographic operations require Rust.**
- On macOS, you may need to run:
  ```bash
  brew install openssl
  export LDFLAGS="-L/usr/local/opt/openssl/lib"
  export CPPFLAGS="-I/usr/local/opt/openssl/include"
  ```
- On Linux, install OpenSSL development headers:
  ```bash
  sudo apt-get install libssl-dev
  ```
- For more help, see the [Development Guide](../development.md) or open an issue on [GitHub](https://github.com/bradh11/certmonitor).
