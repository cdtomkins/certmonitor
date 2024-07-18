from .base import BaseValidator


class SubjectAltNamesValidator(BaseValidator):
    """
    A validator for checking the Subject Alternative Names (SANs) in an SSL certificate.

    Attributes:
        name (str): The name of the validator.
    """

    name = "subject_alt_names"

    def validate(self, cert, host, port, alternate_names=None):
        """
        Validates the SANs in the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname to validate against the SANs.
            port (int): The port number.
            alternate_names (list, optional): A list of alternate names to validate against the SANs.

        Returns:
            dict: A dictionary containing the validation results, including whether the SANs are valid,
                  the SANs themselves, the count of SANs, and any warnings or reasons for validation failure.
        """
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
            "contains_alternate": {},
            "warnings": [],
        }

        # Check if the host is in the SANs
        result["contains_host"], host_reason = self._check_name_in_sans_with_reason(
            host, dns_sans
        )

        # Check for alternate names if provided
        if alternate_names:
            for alternate_name in alternate_names:
                alt_is_valid, alt_reason = self._check_name_in_sans_with_reason(
                    alternate_name, dns_sans
                )
                result["contains_alternate"][alternate_name] = {
                    "is_valid": alt_is_valid,
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

        for alternate_name, alt_result in result["contains_alternate"].items():
            if not alt_result["is_valid"]:
                result["warnings"].append(
                    f"The alternate name {alternate_name} is not included in the SANs: {alt_result['reason']}"
                )

        return result

    def _check_name_in_sans_with_reason(self, name, sans):
        """
        Checks if the given name is present in the SANs and provides a reason.

        Args:
            name (str): The name to check.
            sans (list): The list of SANs.

        Returns:
            tuple: A tuple containing a boolean indicating if the name is present in the SANs,
                   and a reason string.
        """
        if name in sans:
            return True, f"Exact match for {name} found in SANs"
        for san in sans:
            if self._matches_wildcard(name, san):
                return True, f"{name} matches wildcard SAN {san}"
        return False, f"No match found for {name} in SANs"

    def _matches_wildcard(self, hostname, pattern):
        """
        Checks if the given hostname matches a wildcard pattern.

        Args:
            hostname (str): The hostname to check.
            pattern (str): The wildcard pattern to match against.

        Returns:
            bool: True if the hostname matches the wildcard pattern, False otherwise.
        """
        if not pattern.startswith("*."):
            return False

        host_parts = hostname.split(".")
        pattern_parts = pattern[2:].split(".")  # Remove '*.' and split

        if len(host_parts) != len(pattern_parts) + 1:
            return False

        return host_parts[1:] == pattern_parts
