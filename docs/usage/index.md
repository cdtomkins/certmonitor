# CertMonitor: Usage Overview

## Why CertMonitor Exists

CertMonitor was born out of real-world frustration: outages and security incidents caused by expired certificates, missing Subject Alternative Names, or incomplete certificate chains. Like many engineers, I was tired of late-night alerts, broken integrations, and the endless scramble to track down certificate issues before they caused downtime or compliance failures.

I created CertMonitor to solve these pain points with a tool that is:
- **Zero-dependency:** 100% native Python, with optional Rust bindings for advanced cryptography. No third-party Python packages required—ever.
- **Portable and secure:** Works out-of-the-box in any Python environment, with a minimal attack surface.
- **Extensible:** Add your own validators for organization-specific checks, compliance, or custom certificate logic.
- **Fast and reliable:** Designed for high-throughput, concurrent monitoring of many endpoints.

## What Makes CertMonitor Different?

- **Zero Dependencies:** CertMonitor is dependency-free by design. You can drop it into any environment and it just works. (For advanced cryptography, optional Rust bindings will be available, but never required for basic usage.)
- **Native Python First:** All core features use only the Python standard library. This means maximum compatibility, security, and maintainability.
- **Validator System:** Modular, pluggable checks for everything from expiration to hostname validation, key strength, protocol version, and more.
- **Labor of Love:** This is a passion project, not a commercial product. While we strive for production quality, CertMonitor is always improving—and your feedback and contributions are welcome!

## Example: Catching the Issues That Matter

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    print(monitor.validate())
```

CertMonitor will check for expiration, hostname mismatches, missing SANs, weak keys, outdated protocols, and more—right out of the box.

---

> **Note:** CertMonitor is designed to be zero-dependency and portable. If you need advanced cryptography, Rust bindings will be available, but you will never need to install third-party Python packages.
