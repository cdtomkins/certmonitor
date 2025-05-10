# tests/test_validators/test_hostname.py

from certmonitor.validators.hostname import HostnameValidator


def test_hostname_validator(sample_cert):
    validator = HostnameValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)
    assert result["is_valid"]


def test_hostname_validator_mismatch(sample_cert):
    validator = HostnameValidator()
    result = validator.validate({"cert_info": sample_cert}, "invalid.com", 443)
    assert not result["is_valid"]
