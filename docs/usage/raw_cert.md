# Retrieving Raw Certificate Data

```python
with CertMonitor("example.com") as monitor:
    der = monitor.get_raw_der()  # DER bytes
    pem = monitor.get_raw_pem()  # PEM string
```
