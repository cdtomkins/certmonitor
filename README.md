# Certmonitor

A simple tool to monitor the expiration of SSL certificates and parse details.



# Example usage
```python
hostname = "www.microsoft.com"
cert_monitor = CertMonitor(hostname)
cert_info = cert_monitor.check_cert()
cert_info_converted = CertMonitor.convert_tuples_to_dicts(cert_info)

# Print the dictionary with converted tuples to dicts
print(json.dumps(cert_info_converted, indent=4))
```