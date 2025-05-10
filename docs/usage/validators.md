# Enabling/Disabling Validators

You can control which validators are enabled:

```python
with CertMonitor("example.com", enabled_validators=["expiration", "hostname"]) as monitor:
    print(monitor.validate())
```
