import socket
import ssl
import ipaddress
import tempfile
import os

from certmonitor import config
from certmonitor.validators import get_validators


class CertMonitor:
    """
    Class for monitoring and retrieving SSL certificate details from a given host.
    """

    def __init__(
        self,
        host,
        port: int = 443,
        enabled_validators: list = config.DEFAULT_VALIDATORS,
    ):
        """
        Initializes the CertMonitor with the specified host and port.

        Args:
            host (str): The hostname or IP address to retrieve the certificate from.
            port (int, optional): The port to use for the SSL connection. Defaults to 443.
            enabled_validators (list, optional): List of enabled validators. Defaults to None.
        """
        self.host = host
        self.port = port
        self.is_ip = self._is_ip_address(host)
        self.der = None
        self.pem = None
        self.cert_info = None
        self.validators = get_validators()
        self.enabled_validators = enabled_validators or config.ENABLED_VALIDATORS

    def validate(self, validator_args=None):
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
                        args.append(
                            validator_args[validator.name]
                        )  # Pass the list directly
                    else:
                        args.extend(validator_args[validator.name])
                results[validator.name] = validator.validate(*args)
        return results

    def _is_ip_address(self, host):
        """
        Checks if the provided host is an IP address.

        Args:
            host (str): The hostname or IP address to check.

        Returns:
            bool: True if the host is an IP address, False otherwise.
        """
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def fetch_cert(self):
        """
        Fetches the SSL certificate details based on whether the host is an IP address or a hostname.

        Returns:
            dict: The certificate details or an error message.
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

        Returns:
            dict: The certificate details or an error message.
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

        Returns:
            dict: The certificate details or an error message.
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

        Args:
            error_type (str): The type of error.
            message (str): The error message.

        Returns:
            dict: A dictionary containing the error details.
        """
        return {
            "error": error_type,
            "message": message,
            "host": self.host,
            "port": self.port,
        }

    def to_dict_hostname(self, data):
        """
        Converts the certificate data obtained via hostname into a structured dictionary format.

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

        Args:
            pem_cert (str): The PEM formatted certificate.

        Returns:
            dict: A dictionary containing the structured certificate details.
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

    # def _extract_public_key_info(self):
    #     """
    #     Extracts basic public key information from the certificate.

    #     Returns:
    #         dict: A dictionary containing public key information.
    #     """
    #     if not self.der:
    #         return None

    #     try:
    #         # Find the subject public key info section
    #         spki_start = self.der.find(b"\x30\x82")  # Start of the SubjectPublicKeyInfo
    #         if spki_start == -1:
    #             return None

    #         # Extract the algorithm identifier
    #         alg_oid_start = spki_start + 15  # Typical offset to algorithm OID
    #         alg_oid = self.der[
    #             alg_oid_start : alg_oid_start + 9
    #         ]  # 9 bytes for RSA or EC OID

    #         key_info = {}

    #         if alg_oid == b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01":  # RSA OID
    #             key_info["algorithm"] = "RSA"
    #             # Find the modulus (which gives us the key size)
    #             mod_start = self.der.find(b"\x02\x82", spki_start)  # Start of modulus
    #             if mod_start != -1:
    #                 mod_length = struct.unpack(
    #                     ">H", self.der[mod_start + 2 : mod_start + 4]
    #                 )[0]
    #                 key_info["size"] = mod_length * 8  # Convert bytes to bits
    #         elif alg_oid.startswith(b"\x2a\x86\x48\xce\x3d\x02\x01"):  # EC OID
    #             key_info["algorithm"] = "EC"
    #             # Try to determine the curve
    #             curve_oid = self.der[alg_oid_start + 9 : alg_oid_start + 15]
    #             curves = {
    #                 b"\x2a\x86\x48\xce\x3d\x03\x01\x07": "secp256r1",
    #                 b"\x2b\x81\x04\x00\x22": "secp384r1",
    #                 b"\x2b\x81\x04\x00\x23": "secp521r1",
    #             }
    #             key_info["curve"] = curves.get(curve_oid, "unknown")

    #         return key_info

    #     except Exception as e:
    #         print(f"Error extracting public key info: {str(e)}")
    #         return None

    def get_cert_info(self):
        """
        Retrieves and structures the SSL certificate details.

        Returns:
            dict: A dictionary containing the structured certificate details.
        """
        cert = self.fetch_cert()
        if self.is_ip:
            cert_info = self.to_dict_ip(cert)
            self.cert_info = cert_info
            return cert_info
        else:
            cert_info = self.to_dict_hostname(cert)
            self.cert_info = cert_info
            return self.cert_info

    def get_raw_der(self):
        """
        Returns the raw DER format of the certificate.

        Returns:
            bytes: The DER format of the certificate.
        """
        if not self.der:
            self.fetch_cert()
        return self.der

    def get_raw_pem(self):
        """
        Returns the raw PEM format of the certificate.

        Returns:
            str: The PEM format of the certificate.
        """
        if not self.pem:
            self.fetch_cert()
        return self.pem
