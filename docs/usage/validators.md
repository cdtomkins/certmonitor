# Validator System Overview

Validators are modular checks that CertMonitor uses to assess the security and compliance of SSL/TLS certificates and connections. Each validator focuses on a specific aspect—such as expiration, hostname matching, key strength, or protocol version—and returns a structured result indicating success or failure. Validators can be enabled, disabled, or extended with custom logic to fit your organization's needs.

Validators are the core mechanism that makes CertMonitor flexible and powerful for a wide range of certificate monitoring and compliance scenarios.

# Enabling/Disabling Validators

You can control which validators are enabled:

```python
with CertMonitor("example.com", enabled_validators=["expiration", "hostname"]) as monitor:
    print(monitor.validate())
```

# Validator Convenience Methods

## Listing All Validators

You can list all currently registered validators (including built-in and custom ones) using:

```python
from certmonitor.validators import list_validators

print(list_validators())
# Output: ['expiration', 'hostname', 'key_info', 'subject_alt_names', 'root_certificate', 'tls_version', 'weak_cipher']
```

## Getting Enabled Validators

The `get_enabled_validators()` function is a placeholder for retrieving only the enabled validators (for example, if you implement configuration-based enabling/disabling). By default, it returns an empty list:

```python
from certmonitor.validators import get_enabled_validators

print(get_enabled_validators())
# Output: []
```

## Registering Custom Validators

To add your own validator, create a class that inherits from `BaseValidator`, then register it:

```python
from certmonitor.validators import register_validator, BaseValidator, list_validators

class MyCustomValidator(BaseValidator):
    name = "my_custom_validator"
    def validate(self, cert_info, **kwargs):
        # Custom validation logic
        return {"success": True, "reason": "Custom check passed"}

# Register your custom validator
register_validator(MyCustomValidator())

# Now it will appear in list_validators()
print(list_validators())
# Output will include 'my_custom_validator'
```

See the [Custom Validators](../usage/custom_validators.md) usage guide for more details and a template.

## Validator Workflow (Mermaid Diagram)

```mermaid
flowchart TD
    A[Start: CertMonitor.validate()] --> B{Enabled Validators}
    B -->|Expiration| C[Run ExpirationValidator]
    B -->|Hostname| D[Run HostnameValidator]
    B -->|Custom| E[Run CustomValidator]
    C & D & E --> F[Aggregate Results]
    F --> G[Return Validation Report]
```
