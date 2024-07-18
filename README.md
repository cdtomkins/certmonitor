# CertMonitor

CertMonitor is a Python library for monitoring and retrieving SSL certificate details from a given host. It supports hostname and IP-based certificate retrieval and includes built-in validators to check various aspects of the certificate, such as subject alternative names (SANs) and expiration date.

## Installation

To install CertMonitor, you can use pip:

```sh
pip install certmonitor
```

## Usage
### Basic Usage
Here's an example of how to use CertMonitor to retrieve and validate an SSL certificate:
```python
from certmonitor import CertMonitor

# Initialize CertMonitor with a hostname
monitor = CertMonitor("example.com")

# Fetch and print structured certificate details
structured_cert = monitor.get_cert_info()
print("Structured Certificate:")
print(structured_cert)

# Fetch and print raw DER certificate
raw_der = monitor.get_raw_der()
print("Raw DER Certificate:")
print(raw_der)

# Fetch and print raw PEM certificate
raw_pem = monitor.get_raw_pem()
print("Raw PEM Certificate:")
print(raw_pem)

# Validate the certificate using enabled validators
validation_results = monitor.validate()
print("Validation Results:")
print(validation_results)
```

### Using IP Address
You can also use an IPV4 or IPV6 address to retrieve and validate the SSL certificate. 
Some systems require the use of an IP address to retrieve the certificate, especially when the hostname is not resolvable, however, this can be less reliable as the certificate may not match the hostname. It's intended use would be to retrieve the certificate for a specific IP address to try and understand the certificate details for what is hosted on that IP address.
```python
from certmonitor import CertMonitor

# Initialize CertMonitor with an IP address
monitor = CertMonitor("142.250.80.46")

# Fetch and print structured certificate details
structured_cert = monitor.get_cert_info()
print("Structured Certificate:")
print(structured_cert)

# Validate the certificate using enabled validators
validation_results = monitor.validate()
print("Validation Results:")
print(validation_results)

```

## Validators
CertMonitor includes several built-in validators to check various aspects of the SSL certificate. You can enable or disable validators through the enabled_validators parameter when initializing the CertMonitor instance.

### Available Validators
- HostnameValidator: Validates that the hostname matches the certificate's subject alternative names (SANs).
- SubjectAltNamesValidator: Validates the presence and content of the SANs in the certificate.
- ExpirationValidator: Validates that the certificate is not expired.

### Example with Enabled Validators
```python
from certmonitor import CertMonitor

# Initialize CertMonitor with a hostname and specific validators
monitor = CertMonitor(
    "example.com",
    enabled_validators=["hostname", "subject_alt_names", "expiration"]
)

# Fetch and print structured certificate details
structured_cert = monitor.get_cert_info()
print("Structured Certificate:")
print(structured_cert)

# Validate the certificate with additional arguments for validators
validator_args = {
    "subject_alt_names": ["example.com"]
}
validation_results = monitor.validate(validator_args)
print("Validation Results:")
print(validation_results)
```

## Configuration
You can configure CertMonitor by specifying which validators to enable in the enabled_validators parameter. If not specified, it will use the default validators defined in the configuration.

### Environment Variables
CertMonitor can also read the list of enabled validators from an environment variable ENABLED_VALIDATORS. This is useful for configuring the validators without modifying the code.

By default, the following validators are enabled:

- expiration
- hostname

You can override the default validators by setting the ENABLED_VALIDATORS environment variable to a comma-separated list of validator names.

Example:
> export ENABLED_VALIDATORS="expiration,hostname,subject_alt_names"

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
