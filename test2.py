import json

from certmonitor import CertMonitor

# Example usage
if __name__ == "__main__":
    # Test with a hostname
    validators = [
        "subject_alt_names",
        "expiration",
        "hostname",
        "root_certificate",
        "key_info",
    ]
    with CertMonitor("example.com", enabled_validators=validators) as monitor:
        structured_cert = monitor.get_cert_info()
        validation_results = monitor.validate()
        # public_key_info = monitor._extract_public_key_info()
        print("Hostname test:")
        print(json.dumps(structured_cert, indent=2))

        print("\n" + "=" * 50 + "\n")

        print("Validation Results")
        print(json.dumps(validation_results, indent=2))

        print("\n" + "=" * 50 + "\n")

        print("Cipher Results")
        print(json.dumps(monitor.get_cipher_info(), indent=2))

    print("\n" + "=" * 50 + "\n")
