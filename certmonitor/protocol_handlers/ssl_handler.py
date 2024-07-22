# protocol_handlers/ssl_handler.py

import socket
import ssl
from typing import Optional, Dict, Any
from .base import BaseProtocolHandler


class SSLHandler(BaseProtocolHandler):
    """Handles SSL/TLS connections for certificate monitoring.

    This class provides methods to establish SSL connections, fetch raw certificate
    and cipher information, and manage the connection lifecycle.
    """

    def __init__(self, host, port, error_handler):
        super().__init__(host, port, error_handler)
        self.secure_socket = None
        self.der = None
        self.pem = None

    def connect(self, ignore_cert_errors: bool = True) -> Optional[Dict[str, Any]]:
        """Establishes an SSL connection to the specified host and port.

        Args:
            ignore_cert_errors (bool): If True, ignores certificate validation errors. Default is True.

        Returns:
            Optional[Dict[str, Any]]: None if connection is successful,
                                      or a dictionary containing error details if it fails.
        """
        try:
            self.socket = socket.create_connection((self.host, self.port), timeout=10)

            if ignore_cert_errors:
                context = ssl._create_unverified_context()
            else:
                context = ssl.create_default_context()

            self.secure_socket = context.wrap_socket(
                self.socket, server_hostname=self.host
            )
            return None  # Indicating success
        except ssl.SSLError as e:
            return self.error_handler.handle_error(
                "SSLError", str(e), self.host, self.port
            )
        except socket.error as e:
            return self.error_handler.handle_error(
                "SocketError", str(e), self.host, self.port
            )
        except Exception as e:
            return self.error_handler.handle_error(
                "UnknownError", str(e), self.host, self.port
            )

    def check_connection(self):
        """Checks if the SSL connection is still valid."""
        if not self.secure_socket:
            raise ConnectionError("SSL connection not established")
        try:
            # This will raise an exception if the connection is closed
            self.secure_socket.getpeername()
        except Exception:
            raise ConnectionError("SSL connection is no longer valid")

    def fetch_raw_cert(self) -> Dict[str, Any]:
        if not self.secure_socket:
            return self.error_handler.handle_error(
                "ConnectionError",
                "SSL connection not established",
                self.host,
                self.port,
            )
        try:
            self.der = self.secure_socket.getpeercert(binary_form=True)
            if not self.der:
                return self.error_handler.handle_error(
                    "CertificateError",
                    "No certificate received from the server",
                    self.host,
                    self.port,
                )
            self.pem = ssl.DER_cert_to_PEM_cert(self.der)
            cert_dict = self.secure_socket.getpeercert()
            return {"cert_dict": cert_dict, "der": self.der, "pem": self.pem}
        except ssl.SSLError as e:
            return self.error_handler.handle_error(
                "SSLError", str(e), self.host, self.port
            )
        except socket.error as e:
            return self.error_handler.handle_error(
                "SocketError", str(e), self.host, self.port
            )
        except Exception as e:
            return self.error_handler.handle_error(
                "UnknownError", str(e), self.host, self.port
            )

    def fetch_raw_cipher(self):
        """Fetches the raw cipher information from the SSL connection.

        Returns:
            tuple: A tuple containing cipher information (cipher name, protocol version, secret bits).
            dict: An error message if fetching fails.
        """
        try:
            return self.secure_socket.cipher()
        except Exception as e:
            return self.error_handler.handle_error(
                "CipherError", str(e), self.host, self.port
            )

    def get_raw_der(self) -> bytes:
        """Fetches the raw DER-encoded certificate from the SSL connection.

        Returns:
            bytes: The DER-encoded certificate.

        Raises:
            ssl.SSLError: If there's an SSL-related error.
            Exception: For any other unexpected errors.
        """
        try:
            return self.secure_socket.getpeercert(binary_form=True)
        except ssl.SSLError as e:
            raise ssl.SSLError(f"SSL error while fetching DER certificate: {str(e)}")
        except Exception as e:
            raise Exception(
                f"Unexpected error while fetching DER certificate: {str(e)}"
            )

    def close(self):
        """Closes the SSL connection and associated sockets."""
        if self.secure_socket:
            self.secure_socket.close()
        if self.socket:
            self.socket.close()
