# Basic Usage

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_data = monitor.get_cert_info()
    validation_results = monitor.validate()
    print(cert_data)
    print(validation_results)
```

---

**Example Output:**

```
[
  {
    "subject": {
      "countryName": "US",
      "stateOrProvinceName": "California",
      "localityName": "Los Angeles",
      "organizationName": "Internet Corporation for Assigned Names and Numbers",
      "commonName": "www.example.com"
    },
    "issuer": {
      "countryName": "US",
      "organizationName": "DigiCert Inc",
      "commonName": "DigiCert Global G2 TLS RSA SHA256 2020 CA1"
    },
    "version": 3,
    "serialNumber": "075BCEF30689C8ADDF13E51AF4AFE187",
    "notBefore": "Jan 30 00:00:00 2024 GMT",
    "notAfter": "Mar  1 23:59:59 2025 GMT",
    "subjectAltName": {
      "DNS": [
        "www.example.com",
        "example.com"
      ]
    },
    "OCSP": [
      "http://ocsp.digicert.com"
    ],
    "caIssuers": [
      "http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt"
    ],
    "crlDistributionPoints": [
      "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
    ]
  }
]
```

---

**Output Explanation:**

- The output is a list of dictionaries, each representing a certificate (e.g., for a chain).
- `subject` and `issuer`: Details about the certificate owner and the issuing authority.
- `version`, `serialNumber`: Technical certificate metadata.
- `notBefore` / `notAfter`: Validity period of the certificate.
- `subjectAltName`: All DNS names covered by the certificate.
- `OCSP`, `caIssuers`, `crlDistributionPoints`: URLs for revocation checking and issuer certificates.

Depending on your usage, you may also see a second output (not shown here) with validation results, as described in the API documentation.

If you want to see the validation results, refer to the next section or the API reference for details on the structure and meaning of each validator's output.
