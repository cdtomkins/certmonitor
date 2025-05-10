# Context Manager vs Manual Close

The recommended usage is with a context manager (`with ... as ...`). If you do not use a context manager, call `close()` when done:

```python
monitor = CertMonitor("example.com")
cert = monitor.get_cert_info()
monitor.close()
```
