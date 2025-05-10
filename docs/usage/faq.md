# FAQ

**Q: Can I use CertMonitor with self-signed certificates?**
A: Yes, but some validators (like `root_certificate`) will report them as untrusted.

**Q: How do I see all available validators?**
A: Use `from certmonitor.validators import list_validators; print(list_validators())`.

**Q: How do I debug certificate parsing errors?**
A: Check the error message in the returned dictionary and try running with a different host or port.
