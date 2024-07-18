from .base import BaseValidator
import datetime


class ExpirationValidator(BaseValidator):
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
                  the number of days until expiry, and the expiration date.
        """
        now = datetime.datetime.utcnow()
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y GMT"
        )

        is_valid = now < not_after
        days_to_expiry = (not_after - now).days

        return {
            "is_valid": is_valid,
            "days_to_expiry": days_to_expiry,
            "expires_on": not_after.isoformat(),
        }
