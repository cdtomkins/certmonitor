# FAQ

## Frequently Asked Questions (FAQ)

### Can I use CertMonitor with self-signed certificates?

Yes, but some validators (like `root_certificate`) will report them as untrusted.

### How do I see all available validators?

Use:
```python
from certmonitor.validators import list_validators
print(list_validators())
```

### How do I debug certificate parsing errors?

Check the error message in the returned dictionary and try running with a different host or port.

### Why does CertMonitor use only the Python standard library for cryptography?

CertMonitor is designed for maximum portability, security, and maintainability. By relying exclusively on the Python standard library for cryptographic operations, we avoid the risks and complexity of third-party dependencies, reduce the attack surface, and ensure that CertMonitor works out-of-the-box in any Python environment.

### Will CertMonitor support more advanced cryptography or certificate parsing?

Yes! For advanced or performance-critical cryptographic processing, CertMonitor is architected to support optional Rust bindings. This allows us to leverage the speed and safety of Rust for complex operations, while keeping the core tool lightweight and dependency-free for most users.

### How does CertMonitor ensure high performance?

CertMonitor is optimized for speed and concurrency:
- All network and certificate operations are designed to be fast and non-blocking.
- The API supports asynchronous and parallel workflows (see the Performance Tips section for examples).
- For large-scale or batch monitoring, CertMonitor can be run in highly concurrent environments with minimal overhead.
- Future Rust integration will further accelerate heavy cryptographic workloads.

### Is CertMonitor secure?

Security is a top priority. CertMonitor:
- Avoids third-party cryptography libraries unless absolutely necessary.
- Uses secure defaults for all network and certificate operations.
- Is designed to be auditable, with a small, readable codebase.
- Will leverage Rust for critical-path cryptography to minimize memory safety risks.

### Can I extend CertMonitor with custom validators?

Absolutely! CertMonitor is built to be extensible. You can add your own validators to check for organization-specific requirements, compliance rules, or custom certificate properties. See the Certificate Validators section for details and examples.

### What platforms does CertMonitor support?

CertMonitor runs on any platform with Python 3.7+ and does not require any non-standard dependencies. Optional Rust bindings will be distributed as pre-built wheels for all major platforms.
