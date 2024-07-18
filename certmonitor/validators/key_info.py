from .base import BaseValidator


# TODO: Implement the KeyInfoValidator - work in progress
class KeyInfoValidator(BaseValidator):
    """
    A validator for checking the key information of an SSL certificate.

    Attributes:
        name (str): The name of the validator.
    """

    name = "key_info"

    def validate(self, cert, host, port):
        """
        Validates the key information of the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).

        Returns:
            dict: A dictionary containing the validation results, including key type, key size,
                  whether the key is considered strong enough, and curve information if applicable.
        """
        public_key_info = cert.get("public_key_info", {})
        if not public_key_info:
            return {
                "error": "Unable to extract public key information",
                "is_valid": False,
            }

        key_type = public_key_info.get("algorithm", "Unknown")
        key_size = public_key_info.get("size")
        curve = public_key_info.get("curve")

        result = {
            "key_type": key_type,
            "key_size": key_size,
            "is_valid": self._is_key_strong_enough(key_type, key_size, curve),
        }

        if curve:
            result["curve"] = curve

        return result

    def _is_key_strong_enough(self, key_type, key_size, curve):
        """
        Checks if the key is strong enough based on its type, size, and curve.

        Args:
            key_type (str): The type of the key.
            key_size (int): The size of the key.
            curve (str): The curve of the key (if applicable).

        Returns:
            bool or None: True if the key is considered strong enough, False if not, and None if undetermined.
        """
        if "rsaEncryption" in key_type:
            return key_size >= 2048 if key_size else None
        elif "ecPublicKey" in key_type:
            strong_curves = ["secp256r1", "secp384r1", "secp521r1"]
            return curve in strong_curves if curve else None
        return None  # Unable to determine
