# validators/weak_cipher.py

from ..cipher_algorithms import ALLOWED_CIPHER_SUITES
from .base import BaseCipherValidator


class WeakCipherValidator(BaseCipherValidator):
    """
    Validates that the negotiated cipher suite is in the allowed list.
    """

    name = "weak_cipher"

    def validate(self, cipher_info, host, port):
        cipher_suite = cipher_info.get("cipher_suite", {})
        cipher_name = cipher_suite.get("name")

        result = {
            "is_valid": True,
            "cipher_suite": cipher_name,
        }

        if cipher_name not in ALLOWED_CIPHER_SUITES:
            result["is_valid"] = False
            result["reason"] = (
                f"Cipher suite {cipher_name} is not allowed. "
                "Please update your allowed cipher suites or negotiate a supported cipher."
            )

        return result
