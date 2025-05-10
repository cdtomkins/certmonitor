# Troubleshooting

- **Cannot connect to host:** Check network/firewall, host/port, and certificate validity.
- **Validator not found:** Ensure the validator name is correct and available in your CertMonitor version.
- **Unexpected output:** Use `print(json.dumps(result, indent=2))` for easier inspection.
- **SSL/TLS only:** Some features (raw DER/PEM, cipher info) are only available for SSL/TLS, not SSH.
