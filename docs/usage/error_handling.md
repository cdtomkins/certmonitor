# Error Handling

All methods return a dictionary with an `error` key if something goes wrong:

```python
with CertMonitor("badhost") as monitor:
    cert = monitor.get_cert_info()
    if isinstance(cert, dict) and "error" in cert:
        print("Error:", cert["message"])
```

## Error Handling Pathways (Mermaid Diagram)

```mermaid
flowchart TD
    A[CertMonitor Operation] --> B{Error?}
    B -- No --> C[Return Success]
    B -- Yes --> D[ErrorHandler.handle_error()]
    D --> E[Return Structured Error]
```
