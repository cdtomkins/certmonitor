# tests/test_validators/test_expiration.py

from datetime import datetime, timedelta

from certmonitor.validators.expiration import ExpirationValidator


def test_expiration_validator(sample_cert):
    validator = ExpirationValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)
    assert result["is_valid"]
    assert "days_to_expiry" in result


def test_expired_cert(sample_cert):
    sample_cert["notAfter"] = (datetime.now() - timedelta(days=1)).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )
    validator = ExpirationValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)
    assert not result["is_valid"]


if __name__ == "__main__":
    import pytest

    pytest.main()
