# validators/base.py

from abc import ABC, abstractmethod


class BaseValidator(ABC):
    """
    Abstract base class for certificate validators.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Returns the name of the validator.

        Returns:
            str: The name of the validator.
        """

    @abstractmethod
    def validate(self, cert, host, port):
        """
        Validates the given certificate.

        Args:
            cert (dict): The certificate data.
            host (str): The hostname or IP address.
            port (int): The port number.

        Returns:
            dict: The validation result.
        """


class BaseCertValidator(BaseValidator):
    validator_type = "cert"

    def validate(self, cert_info, host, port):
        # cert validation logic
        pass


class BaseCipherValidator(BaseValidator):
    validator_type = "cipher"

    def validate(self, cipher_info, host, port):
        # cipher validation logic
        pass
