# Performance Tips

- Use the context manager to ensure connections are closed promptly.
- For batch testing, use Python's `asyncio` and `asyncio.to_thread` to parallelize checks (see `test.py` for an example).
