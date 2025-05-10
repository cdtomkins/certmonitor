# tests/test_validators/test_subject_alt_names.py

from certmonitor.validators.subject_alt_names import SubjectAltNamesValidator


def test_subject_alt_names_validator(sample_cert):
    validator = SubjectAltNamesValidator()
    result = validator.validate(
        {"cert_info": sample_cert}, "www.example.com", 443, ["example.com"]
    )
    assert result["is_valid"]
    assert result["contains_host"]["is_valid"]
    assert result["contains_alternate"]["example.com"]["is_valid"]


def test_subject_alt_names_validator_mismatch(sample_cert):
    validator = SubjectAltNamesValidator()
    result = validator.validate(
        {"cert_info": sample_cert}, "www.example.com", 443, ["invalid.com"]
    )
    assert result["is_valid"]
    assert result["contains_host"]["is_valid"]
    assert not result["contains_alternate"]["invalid.com"]["is_valid"]
