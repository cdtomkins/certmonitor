# Context Manager vs Manual Close

CertMonitor supports both context manager (with ... as ...) and manual open/close usage patterns.

## Recommended: Context Manager

The context manager ensures connections are always closed, even if an error occurs.

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

---

## Manual Open/Close

You can also manage the connection manually:

```python
monitor = CertMonitor("example.com")
monitor.connect()
try:
    cert_info = monitor.get_cert_info()
    print(cert_info)
finally:
    monitor.close()
```

---

## Example Output

Both styles return the same results:

```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"organizationName": "DigiCert Inc"},
  "notBefore": "2024-06-01T00:00:00",
  "notAfter": "2025-09-01T23:59:59"
  // ...
}
```

---

> **Tip:** Always use the context manager unless you have a specific reason to manage connections manually (e.g., advanced connection pooling).
