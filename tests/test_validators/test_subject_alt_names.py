from certmonitor.validators.subject_alt_names import SubjectAltNamesValidator


def test_subject_alt_names_validator(sample_cert):
    validator = SubjectAltNamesValidator()
    result = validator.validate(sample_cert, "www.example.com", 443, ["example.com"])
    print(result)
    assert result["is_valid"] == True
    assert result["contains_host"] == True
    assert result["contains_alternate"]["example.com"]["is_valid"] == True


def test_subject_alt_names_validator_mismatch(sample_cert):
    validator = SubjectAltNamesValidator()
    result = validator.validate(sample_cert, "www.example.com", 443, ["invalid.com"])
    assert result["is_valid"] == True
    assert result["contains_host"] == True
    assert result["contains_alternate"]["invalid.com"]["is_valid"] == False
