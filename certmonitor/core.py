import socket
import ssl
import ipaddress
import tempfile
import os
from typing import Optional, Dict, Any
import logging

from certmonitor import config
from certmonitor.validators import get_validators
from certmonitor.error_handlers import ErrorHandler
from certmonitor.cipher_algorithms import parse_cipher_suite
from certmonitor.protocol_handlers.ssl_handler import SSLHandler
from certmonitor.protocol_handlers.ssh_handler import SSHHandler


class CertMonitor:
    """Class for monitoring and retrieving certificate details from a given host."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        enabled_validators: list = config.DEFAULT_VALIDATORS,
    ):
        """Initialize the CertMonitor with the specified host and port."""
        self.host = host
        self.port = port
        self.is_ip = self._is_ip_address(host)
        self.der = None
        self.pem = None
        self.cert_info = None
        self.validators = get_validators()
        self.enabled_validators = enabled_validators or config.ENABLED_VALIDATORS
        self.error_handler = ErrorHandler()
        self.handler = None
        self.protocol = None
        self.connected = False

    def __enter__(self):
        """Enter the runtime context related to this object."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Exit the runtime context related to this object."""
        self.close()

    def connect(self) -> Optional[Dict[str, Any]]:
        """Establishes a connection to the host if not already connected."""
        if self.connected:
            logging.debug("Already connected, skipping connection attempt")
            return None

        self.protocol = self.detect_protocol()
        if isinstance(self.protocol, dict) and "error" in self.protocol:
            return self.protocol

        if self.protocol == "ssl":
            self.handler = SSLHandler(self.host, self.port, self.error_handler)
        elif self.protocol == "ssh":
            self.handler = SSHHandler(self.host, self.port, self.error_handler)
        else:
            return self.error_handler.handle_error(
                "ProtocolError",
                f"Unsupported protocol: {self.protocol}",
                self.host,
                self.port,
            )

        connection_result = self.handler.connect()
        if connection_result is not None:  # This means there was an error
            return connection_result

        self.connected = True
        logging.debug(f"Successfully connected to {self.host}:{self.port}")
        return None

    def close(self):
        """Close the connection and reset the handler."""
        if self.handler:
            self.handler.close()
        self.handler = None

    def detect_protocol(self):
        """Detect the protocol used by the host."""
        try:
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                sock.setblocking(False)
                try:
                    data = sock.recv(4, socket.MSG_PEEK)
                    if data.startswith(b"SSH-"):
                        return "ssh"
                    elif data[0] in [22, 128, 160]:  # Common first bytes for SSL/TLS
                        return "ssl"
                    else:
                        return self.error_handler.handle_error(
                            "ProtocolDetectionError",
                            f"Unable to determine protocol. First bytes: {data.hex()}",
                            self.host,
                            self.port,
                        )
                except socket.error:
                    # If no data is received, assume it's SSL
                    return "ssl"
                finally:
                    sock.setblocking(True)
        except Exception as e:
            return self.error_handler.handle_error("ConnectionError", str(e), self.host, self.port)

    def _ensure_connection(self):
        """Ensures that a valid connection is established."""
        if not self.connected:
            connect_result = self.connect()
            if connect_result is not None:  # This means there was an error
                raise ConnectionError(f"Failed to establish connection: {connect_result}")
        else:
            try:
                self.handler.check_connection()
            except ConnectionError:
                logging.warning("Connection lost, attempting to reconnect")
                self.connected = False
                connect_result = self.connect()
                if connect_result is not None:  # This means there was an error
                    raise ConnectionError(f"Failed to re-establish connection: {connect_result}")

    def _is_ip_address(self, host: str) -> bool:
        """Check if the provided host is an IP address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _fetch_raw_cert(self) -> Dict[str, Any]:
        """Fetches the raw certificate from the connected host."""
        self._ensure_connection()
        cert_data = self.handler.fetch_raw_cert()

        if isinstance(cert_data, dict) and "error" in cert_data:
            return cert_data

        cert_dict = cert_data["cert_dict"]
        self.der = cert_data["der"]
        self.pem = cert_data["pem"]

        if not cert_dict:
            # If getpeercert() returns an empty dict, we'll parse the cert ourselves
            cert_dict = self._parse_pem_cert(self.pem)

        return cert_dict

    def _fetch_raw_cipher(self) -> tuple:
        """Fetch the raw cipher information."""
        self._ensure_connection()
        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "Cipher information is only available for SSL/TLS connections",
                self.host,
                self.port,
            )
        return self.handler.fetch_raw_cipher()

    def _parse_pem_cert(self, pem_cert: str) -> dict:
        """Parse a PEM formatted certificate to extract relevant details."""
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(pem_cert)
            temp_file.flush()
            temp_file_path = temp_file.name

        try:
            cert_details = ssl._ssl._test_decode_cert(temp_file_path)
        finally:
            os.remove(temp_file_path)

        return cert_details

    def _to_structured_dict(self, data) -> dict:
        """Convert the certificate data into a structured dictionary format.

        Args:
            data (dict): The certificate data.

        Returns:
            dict: A dictionary containing the structured certificate data.
        """

        def _handle_duplicate_keys(data):
            result = {}
            for key, value in data:
                if key in result:
                    if not isinstance(result[key], list):
                        result[key] = [result[key]]
                    result[key].append(self._to_structured_dict(value))
                else:
                    result[key] = self._to_structured_dict(value)
            return result

        if isinstance(data, (tuple, list)):
            if all(isinstance(item, tuple) and len(item) == 2 for item in data):
                return _handle_duplicate_keys(data)
            return [self._to_structured_dict(item) for item in data]
        elif isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if key in ["subject", "issuer"]:
                    result[key] = _handle_duplicate_keys([item for sublist in value for item in sublist])
                else:
                    result[key] = self._to_structured_dict(value)
            return result
        else:
            return data

    def get_cert_info(self) -> Dict[str, Any]:
        """Retrieves and structures the certificate details."""
        if not self.cert_info:
            try:
                self._ensure_connection()
                cert = self._fetch_raw_cert()

                if isinstance(cert, dict) and "error" in cert:
                    logging.error(f"Error in fetching raw certificate: {cert}")
                    return cert

                self.cert_info = self._to_structured_dict(cert)

                logging.debug("Certificate info retrieved and structured")
            except Exception as e:
                logging.exception("Error while getting certificate info")
                return self.error_handler.handle_error("UnknownError", str(e), self.host, self.port)

        return self.cert_info

    def get_raw_der(self) -> bytes:
        """Return the raw DER format of the certificate."""
        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "DER format is only available for SSL/TLS connections",
                self.host,
                self.port,
            )

        self._ensure_connection()

        try:
            return self.handler.get_raw_der()
        except Exception as e:
            return self.error_handler.handle_error("CertificateError", str(e), self.host, self.port)

    def get_raw_pem(self) -> str:
        """Return the raw PEM format of the certificate."""
        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "PEM format is only available for SSL/TLS connections",
                self.host,
                self.port,
            )

        self._ensure_connection()

        try:
            der = self.handler.get_raw_der()
            return ssl.DER_cert_to_PEM_cert(der)
        except Exception as e:
            return self.error_handler.handle_error("CertificateError", str(e), self.host, self.port)

    def get_cipher_info(self) -> dict:
        """Retrieve and structure the cipher information of the SSL/TLS connection."""
        raw_cipher = self._fetch_raw_cipher()

        # Check if raw_cipher is an error response
        if isinstance(raw_cipher, dict) and "error" in raw_cipher:
            return raw_cipher

        # If raw_cipher is not an error, it should be a tuple of 3 elements
        if not isinstance(raw_cipher, tuple) or len(raw_cipher) != 3:
            return self.error_handler.handle_error(
                "CipherInfoError", "Unexpected cipher info format", self.host, self.port
            )

        cipher_suite, protocol_version, key_bit_length = raw_cipher
        parsed_cipher = parse_cipher_suite(cipher_suite)

        result = {
            "cipher_suite": {
                "name": cipher_suite,
                "encryption_algorithm": parsed_cipher["encryption"],
                "message_authentication_code": parsed_cipher["mac"],
            },
            "protocol_version": protocol_version,
            "key_bit_length": key_bit_length,
        }

        if protocol_version == "TLSv1.3":
            result["cipher_suite"]["key_exchange_algorithm"] = (
                "Not applicable (TLS 1.3 uses ephemeral key exchange by default)"
            )
        else:
            result["cipher_suite"]["key_exchange_algorithm"] = parsed_cipher["key_exchange"]

        return result

    def validate(self, validator_args=None) -> dict:
        """
        Validates the certificate using the enabled validators.

        Args:
            validator_args (dict, optional): Additional arguments for specific validators. Defaults to None.

        Returns:
            dict: Validation results for each validator.
        """
        if not self.cert_info or "error" in self.cert_info:
            print(
                f"Skipping validation due to error in certificate retrieval: {self.cert_info.get('error', 'Unknown error')}"
            )
            return None

        results = {}
        for validator in self.validators:
            if validator.name in self.enabled_validators:
                args = [self.cert_info, self.host, self.port]
                if validator_args and validator.name in validator_args:
                    if validator.name == "subject_alt_names":
                        args.append(validator_args[validator.name])  # Pass the list directly
                    else:
                        args.extend(validator_args[validator.name])
                results[validator.name] = validator.validate(*args)
        return results
