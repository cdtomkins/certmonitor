# CertMonitor

CertMonitor is a Python library for monitoring and retrieving SSL certificate details from a given host. It supports hostname and IP-based certificate retrieval and includes built-in validators to check various aspects of the certificate, such as subject alternative names (SANs), expiration date, and more.

> CertMonitor is built with a strict philosophy of using only the Python standard library—no third-party dependencies are required. This ensures maximum portability and reliability across all Python environments.

## Installation

If published to PyPI:
```sh
pip install certmonitor
```
If not published, clone this repository and install locally:
```sh
git clone <repo-url>
cd certmonitor
pip install .
```

## Usage

### Context Manager Usage (Recommended)
```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_data = monitor.get_cert_info()
    validation_results = monitor.validate(validator_args={"subject_alt_names": ["www.example.com"]})
    print(cert_data)
    print(validation_results)
```

### Basic Usage (Non-Context Manager)
```python
monitor = CertMonitor("example.com")
cert_data = monitor.get_cert_info()
validation_results = monitor.validate()
monitor.close()
```

### Using IP Address
You can also use an IPv4 or IPv6 address to retrieve and validate the SSL certificate. Note: Using an IP address may not match the certificate's hostname.
```python
with CertMonitor("20.76.201.171") as monitor:
    cert = monitor.get_cert_info()
    validation_results = monitor.validate()
    print(cert)
    print(validation_results)
```

### Retrieving Raw Certificate Data
These methods are only available for SSL/TLS connections:
```python
raw_der = monitor.get_raw_der()  # Returns DER bytes
raw_pem = monitor.get_raw_pem()  # Returns PEM string
```

### Retrieving Cipher Information
You can retrieve and validate cipher suite information:
```python
cipher_info = monitor.get_cipher_info()
print(cipher_info)
```

## Validators
CertMonitor includes several built-in validators to check various aspects of the SSL certificate and connection. You can enable or disable validators through the `enabled_validators` parameter when initializing the CertMonitor instance.

### Available Validators
- `expiration`: Validates that the certificate is not expired.
- `hostname`: Validates that the hostname matches the certificate's subject alternative names (SANs).
- `subject_alt_names`: Validates the presence and content of the SANs in the certificate.
- `root_certificate`: Validates if the certificate is issued by a trusted root CA.
- `key_info`: Validates the public key type and strength.
- `tls_version`: Validates the negotiated TLS version.
- `weak_cipher`: Validates that the negotiated cipher suite is in the allowed list.

### Example with Enabled Validators
```python
with CertMonitor(
    "example.com",
    enabled_validators=["hostname", "subject_alt_names", "expiration", "root_certificate", "key_info", "tls_version", "weak_cipher"]
) as monitor:
    cert = monitor.get_cert_info()
    # Pass extra arguments to any validator that supports them
    validator_args = {"subject_alt_names": ["example.com"]}
    validation_results = monitor.validate(validator_args)
    print(validation_results)
```

### Passing Arguments to Validators
You can pass extra arguments to any validator that supports them using the `validator_args` dictionary:
```python
validator_args = {
    "subject_alt_names": ["example.com", "www.example.com"],
    # Add more if needed for other validators
}
results = monitor.validate(validator_args)
```

## Configuration
You can configure CertMonitor by specifying which validators to enable in the `enabled_validators` parameter. If not specified, it will use the default validators defined in the configuration.

### Default Validators
By default, the following validators are enabled:
- expiration
- hostname
- root_certificate

### Environment Variables
CertMonitor can also read the list of enabled validators from an environment variable `ENABLED_VALIDATORS`. This is useful for configuring the validators without modifying the code.

Example:
```sh
export ENABLED_VALIDATORS="expiration,hostname,subject_alt_names,root_certificate,key_info,tls_version,weak_cipher"
```

## Protocol Detection
CertMonitor automatically detects the protocol (SSL/TLS or SSH) for the target host. Most features are focused on SSL/TLS. SSH support is limited.

## Error Handling
If an error occurs (e.g., connection failure, invalid certificate), CertMonitor methods will return a dictionary with an `error` key and details. Always check for errors in returned data:
```python
cert = monitor.get_cert_info()
if isinstance(cert, dict) and "error" in cert:
    print("Error:", cert["message"])
```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
