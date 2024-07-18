from certmonitor import CertMonitor
import json


# Example usage
if __name__ == "__main__":
    # Test with a hostname
    monitor = CertMonitor("example.com")
    structured_cert = monitor.get_structured_cert()
    print("Hostname test:")
    print(json.dumps(structured_cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv4 address
    monitor = CertMonitor("20.76.201.171")  # IPv4 for example.com
    structured_cert = monitor.get_structured_cert()
    print("IPv4 test:")
    print(json.dumps(structured_cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv6 address
    monitor = CertMonitor("2606:2800:220:1:248:1893:25c8:1946")  # IPv6 for example.com
    structured_cert = monitor.get_structured_cert()
    print("IPv6 test:")
    print(json.dumps(structured_cert, indent=2))
