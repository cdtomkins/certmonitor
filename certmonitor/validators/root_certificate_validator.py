# validators/root_certificate_validator.py

from .base import BaseCertValidator


class RootCertificateValidator(BaseCertValidator):
    """
    A validator for checking if the SSL certificate is issued by a trusted root CA.

    Attributes:
        name (str): The name of the validator.
    """

    name = "root_certificate"

    def validate(self, cert, host, port):
        """
        Validates if the SSL certificate is issued by a trusted root CA.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).

        Returns:
            dict: A dictionary containing the validation results, including whether the certificate is valid,
                  and any warnings or reasons for validation failure.
        """
        issuer = cert.get("issuer", {})
        subject = cert.get("subject", {})
        common_name = issuer.get("commonName", "Unknown")
        organization_name = issuer.get("organizationName", "Unknown")

        # Check for presence of OCSP and caIssuers fields
        has_ocsp = "OCSP" in cert
        has_ca_issuers = "caIssuers" in cert

        # Check if the certificate is self-signed
        is_self_signed = issuer == subject

        # Heuristic check: If the issuer's common name or organization name contains 'Untrusted', flag it
        is_trusted = (
            (has_ocsp and has_ca_issuers)
            and not is_self_signed
            and ("untrusted" not in common_name.lower() and "untrusted" not in organization_name.lower())
        )

        warnings = []
        if not has_ocsp:
            warnings.append("Certificate does not provide OCSP information.")
        if not has_ca_issuers:
            warnings.append("Certificate does not provide caIssuers information.")
        if is_self_signed:
            warnings.append("Certificate is self-signed.")
        if not is_trusted:
            warnings.append(f"The certificate is issued by an untrusted root CA: {organization_name} ({common_name})")

        return {
            "is_valid": is_trusted,
            "issuer": issuer,
            "warnings": warnings,
        }
