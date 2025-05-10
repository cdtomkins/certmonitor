# Using IP Addresses

You can use IPv4 or IPv6 addresses as the target. Note that certificate validation may fail if the certificate does not match the IP address.

```python
with CertMonitor("8.8.8.8") as monitor:
    cert = monitor.get_cert_info()
    print(cert)
```
