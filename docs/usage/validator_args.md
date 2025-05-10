# Passing Arguments to Validators

Some validators accept extra arguments via `validator_args`:

```python
with CertMonitor("example.com", enabled_validators=["subject_alt_names"]) as monitor:
    args = {"subject_alt_names": ["example.com", "www.example.com"]}
    print(monitor.validate(validator_args=args))
```
