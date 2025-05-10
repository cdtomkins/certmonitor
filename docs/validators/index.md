# Validators Overview

CertMonitor provides a modular validator system to check various aspects of SSL/TLS certificates and connections. Each validator can be enabled or disabled as needed, and some accept additional arguments for fine-grained control.

Available validators:

- [Expiration](expiration.md): Checks if the certificate is expired or expiring soon.
- [Hostname](hostname.md): Validates that the certificate matches the expected hostname.
- [SubjectAltNames](subject_alt_names.md): Checks the Subject Alternative Names (SANs) extension.
- [RootCertificate](root_certificate.md): Checks if the certificate is issued by a trusted root CA.
- [KeyInfo](key_info.md): Validates the public key type and strength.
- [TLSVersion](tls_version.md): Validates the negotiated TLS version.
- [WeakCipher](weak_cipher.md): Validates that the negotiated cipher suite is in the allowed list.

See each page for usage and output examples.

---

# Expiration Validator

::: certmonitor.validators.expiration.ExpirationValidator

# Hostname Validator

::: certmonitor.validators.hostname.HostnameValidator

# SubjectAltNames Validator

::: certmonitor.validators.subject_alt_names.SubjectAltNamesValidator

# RootCertificate Validator

::: certmonitor.validators.root_certificate_validator.RootCertificateValidator

# KeyInfo Validator

::: certmonitor.validators.key_info.KeyInfoValidator

# TLSVersion Validator

::: certmonitor.validators.tls_version.TLSVersionValidator

# WeakCipher Validator

::: certmonitor.validators.weak_cipher.WeakCipherValidator
