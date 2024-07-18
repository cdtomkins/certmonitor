from .base import BaseValidator


class KeyInfoValidator(BaseValidator):
    name = "key_info"

    def validate(self, cert, host, port):
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
        if "rsaEncryption" in key_type:
            return key_size >= 2048 if key_size else None
        elif "ecPublicKey" in key_type:
            strong_curves = ["secp256r1", "secp384r1", "secp521r1"]
            return curve in strong_curves if curve else None
        return None  # Unable to determine
