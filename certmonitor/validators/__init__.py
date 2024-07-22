from .expiration import ExpirationValidator
from .hostname import HostnameValidator
from .key_info import KeyInfoValidator
from .subject_alt_names import SubjectAltNamesValidator
from .root_certificate_validator import RootCertificateValidator
# ... import other validators


def get_validators():
    return [
        ExpirationValidator(),
        HostnameValidator(),
        KeyInfoValidator(),
        SubjectAltNamesValidator(),
        RootCertificateValidator(),
        # ... other validators
    ]
