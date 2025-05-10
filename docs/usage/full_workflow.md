# Full Workflow Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=[
    "expiration", "hostname", "subject_alt_names", "root_certificate", "key_info", "tls_version", "weak_cipher"
]) as monitor:
    cert = monitor.get_cert_info()
    print("Certificate Info:", cert)
    validator_args = {"subject_alt_names": ["example.com", "www.example.com"]}
    results = monitor.validate(validator_args=validator_args)
    print("Validation Results:", results)
    cipher_info = monitor.get_cipher_info()
    print("Cipher Info:", cipher_info)
```
