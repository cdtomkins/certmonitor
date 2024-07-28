import pytest

from certmonitor import CertMonitor


@pytest.fixture
def sample_cert():
    return {
        "subject": {
            "countryName": "US",
            "stateOrProvinceName": "California",
            "localityName": "Los Angeles",
            "organizationName": "Internet\u00a0Corporation\u00a0for\u00a0Assigned\u00a0Names\u00a0and\u00a0Numbers",
            "commonName": "www.example.org",
        },
        "issuer": {
            "countryName": "US",
            "organizationName": "DigiCert Inc",
            "commonName": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
        },
        "version": 3,
        "serialNumber": "075BCEF30689C8ADDF13E51AF4AFE187",
        "notBefore": "Jan 30 00:00:00 2024 GMT",
        "notAfter": "Mar  1 23:59:59 2025 GMT",
        "subjectAltName": {
            "DNS": [
                "www.example.org",
                "example.net",
                "example.edu",
                "example.com",
                "example.org",
                "www.example.com",
                "www.example.edu",
                "www.example.net",
            ]
        },
        "OCSP": ["http://ocsp.digicert.com"],
        "caIssuers": ["http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt"],
        "crlDistributionPoints": [
            "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
            "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        ],
    }


@pytest.fixture
def cert_monitor():
    return CertMonitor("www.example.com")
