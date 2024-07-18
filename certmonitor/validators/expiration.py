from .base import BaseValidator
import datetime


class ExpirationValidator(BaseValidator):
    name = "expiration"

    def validate(self, cert, host, port):
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
