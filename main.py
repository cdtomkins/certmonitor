from certmonitor import CertMonitor
import json


# Example usage
if __name__ == "__main__":
    # Test with a hostname
    monitor = CertMonitor(
        "google.com",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    )
    structured_cert = monitor.get_structured_cert()
    validation_results = monitor.validate(
        validator_args={"subject_alt_names": ["doodoo.google.com"]}
    )
    # public_key_info = monitor._extract_public_key_info()
    print("Hostname test:")
    print(json.dumps(structured_cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv4 address
    monitor = CertMonitor(
        "20.76.201.171",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    )  # IPv4 for example.com
    structured_cert = monitor.get_structured_cert()
    validation_results = monitor.validate(
        validator_args={"subject_alt_names": ["doodoo.google.com"]}
    )
    print("IPv4 test:")
    print(json.dumps(structured_cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv6 address
    monitor = CertMonitor(
        "2606:2800:220:1:248:1893:25c8:1946",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    )  # IPv6 for example.com
    structured_cert = monitor.get_structured_cert()
    validation_results = monitor.validate(
        validator_args={"subject_alt_names": ["doodoo.google.com"]}
    )
    print("IPv6 test:")
    print(json.dumps(structured_cert, indent=2))

    # Test with an hostname with very few SANS
    monitor = CertMonitor(
        "www.networktocode.com",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    )
    structured_cert = monitor.get_structured_cert()
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
    structured_cert = monitor.get_structured_cert()
    validation_results = monitor.validate(
        validator_args={"subject_alt_names": ["cisco.com"]}
    )
    print("Hostname with few SANS:")
    print(json.dumps(structured_cert, indent=2))
