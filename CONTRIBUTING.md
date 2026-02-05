# Contributing

Thank you for improving llm-security-proxy! Please follow these guidelines:

- Use Python 3.10+.
- Install dev deps with `pip install -r requirements-dev.txt`.
- Run `ruff check .` and `pytest` before sending changes.
- Keep logging redaction intact—avoid storing raw prompts or secrets anywhere.
- Update tests and documentation when changing behavior.
- Small, focused pull requests are easier to review.
