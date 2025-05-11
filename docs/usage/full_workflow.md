# Full Workflow Example

This page demonstrates a complete CertMonitor workflow, including certificate retrieval, validation, cipher info, and error handling.

## Example: All-in-One

```python
from certmonitor import CertMonitor
import json

validators = [
    "subject_alt_names", "expiration", "hostname", "root_certificate", "key_info", "tls_version", "weak_cipher"
]

with CertMonitor("example.com", enabled_validators=validators) as monitor:
    cert_info = monitor.get_cert_info()
    print("Certificate Info:")
    print(json.dumps(cert_info, indent=2))

    validation_results = monitor.validate()
    print("Validation Results:")
    print(json.dumps(validation_results, indent=2))

    cipher_info = monitor.get_cipher_info()
    print("Cipher Info:")
    print(json.dumps(cipher_info, indent=2))

    pem = monitor.get_raw_pem()
    print("PEM Format:")
    print(pem)

    der = monitor.get_raw_der()
    print("DER Format (base64):")
    import base64
    print(base64.b64encode(der).decode())
```

---

## Example Output (abbreviated)

### Certificate Info
```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"organizationName": "DigiCert Inc"},
  "notBefore": "2024-06-01T00:00:00",
  "notAfter": "2025-09-01T23:59:59"
  // ...
}
```

### Validation Results
```json
{
  "expiration": {"is_valid": true, "days_to_expiry": 120, "expires_on": "2025-09-01T23:59:59", "warnings": []},
  "subject_alt_names": {"is_valid": true, "sans": {"DNS": ["example.com", "www.example.com"], "IP Address": []}, "count": 2, "contains_host": {"name": "example.com", "is_valid": true, "reason": "Matched DNS SAN"}, "contains_alternate": {"www.example.com": {"name": "www.example.com", "is_valid": true, "reason": "Matched DNS SAN"}}, "warnings": []}
  // ...
}
```

### Cipher Info
```json
{
  "cipher_suite": {
    "name": "TLS_AES_256_GCM_SHA384",
    "encryption_algorithm": "AES-256-GCM",
    "message_authentication_code": "AEAD",
    "key_exchange_algorithm": "Not applicable (TLS 1.3 uses ephemeral key exchange by default)"
  },
  "protocol_version": "TLSv1.3",
  "key_bit_length": 256
}
```

### PEM Format
```pem
-----BEGIN CERTIFICATE-----
MIID...snip...IDAQAB
-----END CERTIFICATE-----
```

### DER Format (base64)
```text
MIID...snip...IDAQAB
```

---

## Error Handling Example

If a connection fails, CertMonitor returns a structured error:

```python
with CertMonitor("badhost.invalid") as monitor:
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

Sample output:

```json
{
  "error": "ConnectionError",
  "reason": "[Errno -2] Name or service not known",
  "host": "badhost.invalid",
  "port": 443
}
```

---

> **Tip:** See the [Usage Guide](index.md) for more advanced examples and troubleshooting tips.
