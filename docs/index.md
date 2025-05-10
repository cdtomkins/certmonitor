# CertMonitor Documentation

Welcome to the documentation for CertMonitor, a Python library for monitoring and retrieving SSL certificate details from a given host.

## Features
- 100% Python standard library, no third-party runtime dependencies
- Retrieve and validate SSL/TLS certificates by hostname or IP
- Built-in validators for expiration, hostname, SANs, root CA, key info, TLS version, and cipher strength
- Context manager support for safe resource handling
- Extensible validator system

## Quick Start
```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_data = monitor.get_cert_info()
    validation_results = monitor.validate()
    print(cert_data)
    print(validation_results)
```

See the Usage section for more details.
