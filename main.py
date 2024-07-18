from certmonitor import CertMonitor
import json

# Example usage
if __name__ == "__main__":
    # Test with a hostname
    monitor = CertMonitor(
        "google.com",
        enabled_validators=["subject_alt_names"],
    )
    structured_cert = monitor.get_cert_info()
    validation_results = monitor.validate(
        validator_args={"subject_alt_names": ["doodoo.google.com"]}
    )
    # public_key_info = monitor._extract_public_key_info()
    print("Hostname test:")
    print(json.dumps(structured_cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv4 address
    monitor = CertMonitor("20.76.201.171")  # IPv4 for example.com
    structured_cert = monitor.get_cert_info()
    validation_results = monitor.validate()
    print("IPv4 test:")
    print(json.dumps(structured_cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv6 address
    monitor = CertMonitor("2606:2800:220:1:248:1893:25c8:1946")  # IPv6 for example.com
    structured_cert = monitor.get_cert_info()
    validation_results = monitor.validate()
    print("IPv6 test:")
    print(json.dumps(structured_cert, indent=2))

    # Test with an hostname with very few SANS
    monitor = CertMonitor(
        "www.networktocode.com",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    )
    structured_cert = monitor.get_cert_info()
    validation_results = monitor.validate(
        validator_args={"subject_alt_names": ["networktocode.com"]}
    )
    print("Hostname with few SANS:")
    print(json.dumps(structured_cert, indent=2))

    # Test with an hostname with moderate SANS
    monitor = CertMonitor(
        "www.cisco.com",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    )
    structured_cert = monitor.get_cert_info()
    validation_results = monitor.validate(
        validator_args={"subject_alt_names": ["cisco.com"]}
    )
    print("Hostname with few SANS:")
    print(json.dumps(structured_cert, indent=2))

    # Fetch and print structured certificate details
    structured_cert = monitor.get_cert_info()
    print("Structured Certificate:")
    print(json.dumps(structured_cert, indent=2))

    # Validate the certificate with additional arguments for validators
    validator_args = {"subject_alt_names": ["example.com", "www.example.com"]}
    validation_results = monitor.validate(validator_args)
    print("Validation Results:")
    print(json.dumps(validation_results, indent=2))
