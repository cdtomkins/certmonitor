# protocol_handlers/base.py

from abc import ABC, abstractmethod


class BaseProtocolHandler(ABC):
    def __init__(self, host, port, error_handler):
        self.host = host
        self.port = port
        self.socket = None
        self.secure_socket = None
        self.error_handler = error_handler

    @abstractmethod
    def connect(self):
        pass

    @abstractmethod
    def fetch_raw_cert(self):
        pass

    @abstractmethod
    def close(self):
        pass
