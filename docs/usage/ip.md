# Using IP Addresses

CertMonitor supports both domain names and IP addresses (IPv4 and IPv6) as targets.

## Example: IPv4 Address

```python
from certmonitor import CertMonitor

with CertMonitor("93.184.216.34") as monitor:  # example.com's IPv4
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

---

## Example: IPv6 Address

```python
with CertMonitor("2606:2800:220:1:248:1893:25c8:1946") as monitor:  # example.com's IPv6
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

---

## Example Output

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

## Notes and Edge Cases

- Some hosts may not have certificates for their IP address (validation may fail).
- IPv6 support depends on your system and network configuration.
- If a connection cannot be established, CertMonitor will return a structured error.

---

> **Tip:** You can use all validators and features with IP addresses just as you would with domain names.
