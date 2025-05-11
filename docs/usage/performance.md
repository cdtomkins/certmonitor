# Performance Tips

- Use the context manager to ensure connections are closed promptly.
- For batch testing, use Python's `asyncio` and `asyncio.to_thread` to parallelize checks (see `test.py` for an example).

## Asynchronous Usage for Performance

For best performance when testing many hosts, you can use CertMonitor in an asynchronous workflow. Below is a real-world example using Python's `asyncio` and CertMonitor's thread-safe context manager:

```python
import asyncio
import json
import time
from certmonitor import CertMonitor

start_time = time.time()
total_time = 0
num_tests = 0
print_lock = asyncio.Lock()

async def test_certinfo_async(hostname, port: int = 443):
    global total_time, num_tests
    start = time.time()
    validators = [
        "subject_alt_names",
        "weak_cipher",
        "tls_version",
    ]
    def run_certmonitor():
        lines = []
        with CertMonitor(host=hostname, port=port, enabled_validators=validators) as monitor:
            lines.append(f"Testing {hostname}:{port}")
            cert_details = monitor.get_cert_info()
            lines.append(json.dumps(cert_details, indent=2))
            verification_results = monitor.validate(
                validator_args={
                    "subject_alt_names": [
                        "www.example.com",
                        "cisco.com",
                        "test.google.com",
                        "8.8.4.4",
                        "test.badssl.com",
                    ]
                }
            )
            lines.append(json.dumps(verification_results, indent=2))
            cipher_info = monitor.get_cipher_info()
            lines.append(json.dumps(cipher_info, indent=2))
        return "\n".join(lines)
    output = await asyncio.to_thread(run_certmonitor)
    end = time.time()
    elapsed = end - start
    total_time += elapsed
    num_tests += 1
    chunk = "\n" + "=" * 50 + "\n" + f"{output}\n" + f"Test completed in {elapsed:.2f} seconds\n" + "=" * 50 + "\n"
    async with print_lock:
        print(chunk)
    return elapsed

async def main():
    hosts = [
        ("expired.badssl.com", 443),
        ("8.8.8.8", 443),
        ("example.com", 443),
        ("tls-v1-0.badssl.com", 1010),
        ("tls-v1-1.badssl.com", 1011),
        ("tls-v1-2.badssl.com", 1012),
    ]
    tasks = [test_certinfo_async(host, port) for (host, port) in hosts]
    for task in asyncio.as_completed(tasks):
        try:
            await task
        except Exception as e:
            async with print_lock:
                print("\n" + "=" * 50 + "\n")
                print(f"Test raised an exception: {e}")
                print("=" * 50 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
    end_time = time.time()
    elapsed_time = end_time - start_time
    average_time = total_time / num_tests if num_tests else 0
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
    print(f"Average time per test: {average_time:.2f} seconds")
```

This approach allows you to efficiently test many hosts in parallel, maximizing throughput and minimizing total runtime.
