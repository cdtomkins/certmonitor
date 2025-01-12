# validators/expiration.py

import datetime

from .base import BaseCertValidator


class ExpirationValidator(BaseCertValidator):
    """
    A validator for checking the expiration date of an SSL certificate.

    Attributes:
        name (str): The name of the validator.
    """

    name = "expiration"

    def validate(self, cert, host, port):
        """
        Validates the expiration date of the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).

        Returns:
            dict: A dictionary containing the validation results, including whether the certificate is valid,
                  the number of days until expiry, the expiration date, and any warnings.
        """
        now = datetime.datetime.utcnow()
        not_after = datetime.datetime.strptime(cert["cert_info"]["notAfter"], "%b %d %H:%M:%S %Y GMT")

        is_valid = now < not_after
        days_to_expiry = (not_after - now).days

        warnings = []
        if days_to_expiry < 0:
            warnings.append(f"Certificate is expired and has been expired for ({days_to_expiry} days)")
        if days_to_expiry < 7 and days_to_expiry > 0:
            warnings.append(f"Certificate is expiring in less than 1 week ({days_to_expiry} days)")
        if days_to_expiry > 398:
            warnings.append(f"Certificate is valid for more than industry standard ({days_to_expiry}/398 days)")

        return {
            "is_valid": is_valid,
            "days_to_expiry": days_to_expiry,
            "expires_on": not_after.isoformat(),
            "warnings": warnings,
        }
