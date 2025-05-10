# validators/weak_cipher.py

from ..cipher_algorithms import ALLOWED_CIPHER_SUITES
from .base import BaseCipherValidator


class WeakCipherValidator(BaseCipherValidator):
    """
    Validates that the negotiated cipher suite is in the allowed list.
    """

    name = "weak_cipher"

    def validate(self, cipher_info, host, port):
        """
        Validates that the negotiated cipher suite is in the allowed list.

        Args:
            cipher_info (dict): The cipher information.
            host (str): The hostname.
            port (int): The port number.

        Returns:
            dict: A dictionary containing the validation results, including whether the cipher suite is allowed.

        Examples:
            Example output:
                {
                  "is_valid": true,
                  "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256"
                }
        """
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
