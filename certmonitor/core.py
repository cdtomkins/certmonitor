import socket
import ssl
import ipaddress
import json
import tempfile
import os


class CertMonitor:
    """
    Class for monitoring and retrieving SSL certificate details from a given host.
    """

    def __init__(self, host, port: int = 443):
        """
        Initializes the CertMonitor with the specified host and port.

        :param host: The hostname or IP address to retrieve the certificate from.
        :param port: The port to use for the SSL connection (default is 443).
        """
        self.host = host
        self.port = port
        self.is_ip = self._is_ip_address(host)
        self.der = None
        self.pem = None

    def _is_ip_address(self, host):
        """
        Checks if the provided host is an IP address.

        :param host: The hostname or IP address to check.
        :return: True if the host is an IP address, False otherwise.
        """
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def fetch_cert(self):
        """
        Fetches the SSL certificate details based on whether the host is an IP address or a hostname.

        :return: The certificate details or an error message.
        """
        if self.is_ip:
            cert = self._fetch_cert_by_ip()
            return cert
        else:
            cert = self._fetch_cert_by_hostname()
            return cert

    def _fetch_cert_by_hostname(self):
        """
        Fetches the SSL certificate details using the hostname.

        :return: The certificate details or an error message.
        """
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    self.der = ssock.getpeercert(binary_form=True)
                    self.pem = ssl.DER_cert_to_PEM_cert(self.der)
                    return ssock.getpeercert()
        except ssl.SSLError as e:
            return self._handle_error("SSLError", str(e))
        except socket.error as e:
            return self._handle_error("SocketError", str(e))
        except Exception as e:
            return self._handle_error("UnknownError", str(e))

    def _fetch_cert_by_ip(self):
        """
        Fetches the SSL certificate details using the IP address.

        :return: The certificate details or an error message.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
        try:
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    self.der = ssock.getpeercert(binary_form=True)
                    self.pem = ssl.DER_cert_to_PEM_cert(self.der)
                    return self._parse_pem_cert(self.pem)
        except ssl.SSLError as e:
            return self._handle_error("SSLError", str(e))
        except socket.error as e:
            return self._handle_error("SocketError", str(e))
        except Exception as e:
            return self._handle_error("UnknownError", str(e))

    def _handle_error(self, error_type, message):
        """
        Handles errors encountered during certificate retrieval.

        :param error_type: The type of error.
        :param message: The error message.
        :return: A dictionary containing the error details.
        """
        return {
            "error": error_type,
            "message": message,
            "host": self.host,
            "port": self.port,
        }

    def to_dict_hostname(self, data):
        def _handle_duplicate_keys(data):
            result = {}
            for key, value in data:
                if key in result:
                    if not isinstance(result[key], list):
                        result[key] = [result[key]]
                    result[key].append(self.to_dict_hostname(value))
                else:
                    result[key] = self.to_dict_hostname(value)
            return result

        if isinstance(data, (tuple, list)):
            if all(isinstance(item, tuple) and len(item) == 2 for item in data):
                return _handle_duplicate_keys(data)
            return [self.to_dict_hostname(item) for item in data]
        elif isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if key in ["subject", "issuer"]:
                    result[key] = _handle_duplicate_keys(
                        [item for sublist in value for item in sublist]
                    )
                else:
                    result[key] = self.to_dict_hostname(value)
            return result
        else:
            return data

    def to_dict_ip(self, data):
        """
        Converts the certificate data obtained via IP address into a structured dictionary format.

        :param data: The certificate data.
        :return: A dictionary containing the structured certificate data.
        """

        def _handle_duplicate_keys(data):
            result = {}
            for key, value in data:
                if key in result:
                    if not isinstance(result[key], list):
                        result[key] = [result[key]]
                    result[key].append(self.to_dict_ip(value))
                else:
                    result[key] = self.to_dict_ip(value)
            return result

        if isinstance(data, (tuple, list)):
            if all(isinstance(item, tuple) and len(item) == 2 for item in data):
                return _handle_duplicate_keys(data)
            return [self.to_dict_ip(item) for item in data]
        elif isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if key in ["subject", "issuer"]:
                    result[key] = _handle_duplicate_keys(
                        [item for sublist in value for item in sublist]
                    )
                else:
                    result[key] = self.to_dict_ip(value)
            return result
        else:
            return data

    def _parse_pem_cert(self, pem_cert):
        """
        Parses a PEM formatted certificate to extract relevant details.

        :param pem_cert: The PEM formatted certificate.
        :return: A dictionary containing the structured certificate details.
        """
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(pem_cert)
            temp_file.flush()
            temp_file_path = temp_file.name

        try:
            cert_details = ssl._ssl._test_decode_cert(temp_file_path)
        finally:
            os.remove(temp_file_path)

        return cert_details

    def get_structured_cert(self):
        """
        Retrieves and structures the SSL certificate details.

        :return: A dictionary containing the structured certificate details.
        """
        cert = self.fetch_cert()
        if self.is_ip:
            return self.to_dict_ip(cert)
        else:
            return self.to_dict_hostname(cert)

    def get_raw_der(self):
        """
        Returns the raw DER format of the certificate.

        :return: The DER format of the certificate.
        """
        if not self.der:
            self.fetch_cert()
        return self.der

    def get_raw_pem(self):
        """
        Returns the raw PEM format of the certificate.

        :return: The PEM format of the certificate.
        """
        if not self.pem:
            self.fetch_cert()
        return self.pem
