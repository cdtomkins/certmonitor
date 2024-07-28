from unittest.mock import patch, MagicMock
import socket
from certmonitor import CertMonitor


def test_init():
    monitor = CertMonitor("example.com", 8443, ["expiration", "hostname"])
    assert monitor.host == "example.com"
    assert monitor.port == 8443
    assert monitor.enabled_validators == ["expiration", "hostname"]
    assert not monitor.is_ip


def test_is_ip_address():
    assert CertMonitor("192.168.1.1").is_ip
    assert not CertMonitor("example.com").is_ip


def test_get_cert_info_hostname(cert_monitor, sample_cert):
    with patch.object(cert_monitor, "get_cert_info", return_value=sample_cert):
        result = cert_monitor.get_cert_info()
    assert result == sample_cert


def test_get_cert_info_ip():
    monitor = CertMonitor("192.168.1.1")
    sample_ip_cert = {"subject": {"commonName": "192.168.1.1"}}
    with patch.object(monitor, "get_cert_info", return_value=sample_ip_cert):
        result = monitor.get_cert_info()
    assert result == sample_ip_cert


def test_validate(cert_monitor, sample_cert):
    cert_monitor.cert_info = sample_cert
    with patch.object(cert_monitor, "validators", [MagicMock(name="mock_validator")]):
        cert_monitor.validators[0].name = "mock_validator"
        cert_monitor.enabled_validators = ["mock_validator"]
        result = cert_monitor.validate()
    assert "mock_validator" in result


def test_validate_with_args(cert_monitor, sample_cert):
    cert_monitor.cert_info = sample_cert
    mock_validator = MagicMock(name="subject_alt_names")
    mock_validator.name = "subject_alt_names"
    with patch.object(cert_monitor, "validators", [mock_validator]):
        cert_monitor.enabled_validators = ["subject_alt_names"]
        result = cert_monitor.validate(validator_args={"subject_alt_names": ["example.com"]})
    assert "subject_alt_names" in result
    mock_validator.validate.assert_called_once_with(sample_cert, cert_monitor.host, cert_monitor.port, ["example.com"])


def test_get_raw_der(cert_monitor):
    mock_der = b"mock der data"
    cert_monitor.der = mock_der
    assert cert_monitor.get_raw_der() == mock_der


def test_get_raw_pem(cert_monitor):
    mock_pem = "-----BEGIN CERTIFICATE-----\nmock pem data\n-----END CERTIFICATE-----\n"
    cert_monitor.pem = mock_pem
    assert cert_monitor.get_raw_pem() == mock_pem


def test_fetch_cert_error(cert_monitor):
    # Set the protocol to 'ssl'
    cert_monitor.protocol = "ssl"

    # Mock the _ensure_connection method to do nothing
    with patch.object(cert_monitor, "_ensure_connection"):
        # Mock the ssl_socket attribute
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.side_effect = socket.error("Connection failed")
        cert_monitor.ssl_socket = mock_ssl_socket

        # Call the method we're testing
        result = cert_monitor._fetch_raw_cert()

    # Assert the result
    assert "error" in result
    assert result["error"] == "SocketError"
    assert "Connection failed" in result["message"]
