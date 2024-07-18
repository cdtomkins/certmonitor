from .base import BaseValidator


class SubjectAltNamesValidator(BaseValidator):
    name = "subject_alt_names"

    def validate(self, cert, host, port, alternate_name=None):
        if "subjectAltName" not in cert:
            return {
                "is_valid": False,
                "reason": "Certificate does not contain a Subject Alternative Name extension",
                "sans": None,
                "count": 0,
            }

        sans = cert["subjectAltName"]

        # Ensure sans is a dictionary
        if isinstance(sans, dict):
            dns_sans = sans.get("DNS", [])
            if isinstance(dns_sans, str):
                dns_sans = [dns_sans]
        else:
            dns_sans = [item[1] for item in sans if item[0] == "DNS"]

        result = {
            "is_valid": True,
            "sans": {"DNS": dns_sans},
            "count": len(dns_sans),
            "contains_host": False,
            "contains_alternate": None,
            "warnings": [],
        }

        # Check if the host is in the SANs
        result["contains_host"], host_reason = self._check_name_in_sans_with_reason(
            host, dns_sans
        )

        # Check for alternate name if provided
        if alternate_name:
            alt_is_valid, alt_reason = self._check_name_in_sans_with_reason(
                alternate_name, dns_sans
            )
            result["contains_alternate"] = {
                "is_valid": alt_is_valid,
                "checked_name": alternate_name,
                "reason": alt_reason,
            }

        # Additional checks and warnings
        if not dns_sans:
            result["warnings"].append("Certificate does not contain any DNS SANs")

        if result["count"] > 100:
            result["warnings"].append(
                f"Certificate contains an unusually high number of SANs ({result['count']})"
            )

        if not result["contains_host"]:
            result["warnings"].append(
                f"The hostname {host} is not included in the SANs: {host_reason}"
            )

        if alternate_name and not result["contains_alternate"]["is_valid"]:
            result["warnings"].append(
                f"The alternate name {alternate_name} is not included in the SANs: {alt_reason}"
            )

        return result

    def _check_name_in_sans_with_reason(self, name, sans):
        if name in sans:
            return True, f"Exact match for {name} found in SANs"
        for san in sans:
            if self._matches_wildcard(name, san):
                return True, f"{name} matches wildcard SAN {san}"
        return False, f"No match found for {name} in SANs"

    def _matches_wildcard(self, hostname, pattern):
        if not pattern.startswith("*."):
            return False

        host_parts = hostname.split(".")
        pattern_parts = pattern[2:].split(".")  # Remove '*.' and split

        if len(host_parts) != len(pattern_parts) + 1:
            return False

        return host_parts[1:] == pattern_parts
