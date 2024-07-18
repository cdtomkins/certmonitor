from abc import ABC, abstractmethod


class BaseValidator(ABC):
    @property
    @abstractmethod
    def name(self):
        pass

    @abstractmethod
    def validate(self, cert, host, port):
        pass
