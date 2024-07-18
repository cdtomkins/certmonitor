from .base import BaseValidator


class HostnameValidator(BaseValidator):
    name = "hostname"

    def validate(self, cert, host, port):
        if "subjectAltName" not in cert:
            return {
                "is_valid": False,
                "reason": "Certificate does not contain a Subject Alternative Name extension",
            }

        sans = cert["subjectAltName"]

        # Ensure sans is a list of DNS names
        if isinstance(sans, dict):
            dns_names = sans.get("DNS", [])
            if isinstance(dns_names, str):
                dns_names = [dns_names]
        else:
            dns_names = [item[1] for item in sans if item[0] == "DNS"]

        if not dns_names:
            return {
                "is_valid": False,
                "reason": "Certificate does not contain any DNS SANs",
                "alt_names": [],
            }

        # Check if the hostname matches any of the DNS names
        if self._matches_hostname(host, dns_names):
            return {"is_valid": True, "matched_name": host, "alt_names": dns_names}

        # If no match found, check for wildcard certificates
        for name in dns_names:
            if self._matches_wildcard(host, name):
                return {"is_valid": True, "matched_name": name, "alt_names": dns_names}

        return {
            "is_valid": False,
            "reason": f"Hostname {host} doesn't match any of the certificate's subject alternative names",
            "alt_names": dns_names,
        }

    def _matches_hostname(self, hostname, cert_names):
        return hostname.lower() in (name.lower() for name in cert_names)

    def _matches_wildcard(self, hostname, pattern):
        if not pattern.startswith("*."):
            return False

        host_parts = hostname.split(".")
        pattern_parts = pattern[2:].split(".")  # Remove '*.' and split

        if len(host_parts) != len(pattern_parts) + 1:
            return False

        return host_parts[1:] == pattern_parts
