# validators/tls_version.py

from ..cipher_algorithms import ALLOWED_TLS_VERSIONS
from .base import BaseCipherValidator


class TLSVersionValidator(BaseCipherValidator):
    """
    Checks if the negotiated TLS version is in the allowed list.
    """

    name = "tls_version"

    def validate(self, cipher_info, host, port):
        protocol_version = cipher_info.get("protocol_version")
        result = {
            "is_valid": True,
            "protocol_version": protocol_version,
        }

        if protocol_version not in ALLOWED_TLS_VERSIONS:
            result["is_valid"] = False
            result["reason"] = (
                f"TLS version {protocol_version} is not allowed. "
                "Update your allowed TLS versions or negotiate a supported version."
            )

        return result
