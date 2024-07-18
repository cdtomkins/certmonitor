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
        pass

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
        pass
