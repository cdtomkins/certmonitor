# Passing Arguments to Validators

Some validators accept additional arguments to customize their behavior. You can pass these arguments as a dictionary to the `validate()` method.

## Example: Passing Alternate Names to the subject_alt_names Validator

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    results = monitor.validate({
        "subject_alt_names": ["example.com", "www.example.com", "test.example.com"]
    })
    print(results["subject_alt_names"])
```

### Example Output

```json
{
  "is_valid": true,
  "sans": {"DNS": ["example.com", "www.example.com"], "IP Address": []},
  "count": 2,
  "contains_host": {"name": "example.com", "is_valid": true, "reason": "Matched DNS SAN"},
  "contains_alternate": {
    "www.example.com": {"name": "www.example.com", "is_valid": true, "reason": "Matched DNS SAN"},
    "test.example.com": {"name": "test.example.com", "is_valid": false, "reason": "No match found for test.example.com in DNS SANs: example.com, www.example.com"}
  },
  "warnings": [
    "The alternate name test.example.com is not included in the SANs: No match found for test.example.com in DNS SANs: example.com, www.example.com"
  ]
}
```

---

## Example: Passing Arguments to a Custom Validator

If you implement your own validator that accepts arguments, you can pass them in the same way:

```python
def my_custom_validator(cert, host, port, my_arg):
    # ...
    return {"is_valid": True, "custom": my_arg}

with CertMonitor("example.com") as monitor:
    results = monitor.validate({
        "my_custom_validator": ["my-value"]
    })
    print(results["my_custom_validator"])
```

---

> **Tip:** See the [Validators Reference](../validators/index.md) for details on which validators accept arguments and the expected format.
