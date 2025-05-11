# Retrieving Cipher Information

CertMonitor makes it easy to retrieve detailed information about the cipher suite used in an SSL/TLS connection.

## Example: Getting Cipher Info

You can use the `get_cipher_info()` method to retrieve structured information about the negotiated cipher suite:

```python
from certmonitor import CertMonitor
import json

with CertMonitor("example.com") as monitor:
    cipher_info = monitor.get_cipher_info()
    print(json.dumps(cipher_info, indent=2))
```

### Example Output

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

- The `cipher_suite` object contains the negotiated cipher suite name and its parsed components.
- `protocol_version` shows the TLS version in use.
- `key_bit_length` is the size of the encryption key.

See also: [API Reference: CertMonitor.get_cipher_info()](../reference/certmonitor.md#get_cipher_info)
