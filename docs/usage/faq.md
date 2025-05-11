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

CertMonitor is designed for maximum portability, security, and maintainability. All orchestration and logic is pure Python stdlib, but robust certificate parsing and elliptic curve support are powered by Rust bindings. By relying on Rust for these critical operations, we ensure speed, safety, and correctness—while avoiding third-party Python dependencies.

### Will CertMonitor support more advanced cryptography or certificate parsing?

Yes! For advanced or performance-critical cryptographic processing, CertMonitor is architected to leverage Rust bindings for public key parsing and elliptic curve support. This allows us to use the speed and safety of Rust for complex operations, while keeping the core tool lightweight and dependency-free for orchestration and logic.

### How does CertMonitor ensure high performance?

CertMonitor is optimized for speed and concurrency:
- All network and certificate operations are designed to be fast and non-blocking.
- The API supports asynchronous and parallel workflows (see the Performance Tips section for examples).
- For large-scale or batch monitoring, CertMonitor can be run in highly concurrent environments with minimal overhead.
- Future Rust integration will further accelerate heavy cryptographic workloads and expand advanced crypto support.

### Is CertMonitor secure?

Security is a top priority. CertMonitor:
- Avoids third-party cryptography libraries unless absolutely necessary.
- Uses secure defaults for all network and certificate operations.
- Is designed to be auditable, with a small, readable codebase.
- Will leverage Rust for critical-path cryptography to minimize memory safety risks and enable advanced features.

### Can I extend CertMonitor with custom validators?

Absolutely! CertMonitor is built to be extensible. You can add your own validators to check for organization-specific requirements, compliance rules, or custom certificate properties. See the Certificate Validators section for details and examples.

### What platforms does CertMonitor support?

CertMonitor runs on any platform with Python 3.8+ and does not require any non-standard dependencies for orchestration or logic. Rust is only needed for advanced public key and elliptic curve features. Pre-built wheels are provided for major platforms where available—see the installation instructions for details.
