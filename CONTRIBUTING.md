# Contributing

Thank you for improving the OES-32 Membrane Shield. Keep changes small, explicit, and easy to review. This project values correctness of state transitions over cleverness.

## Before opening a pull request

Run the same checks used by continuous integration:

```bash
python -m pip install -e . pytest ruff mypy
ruff format --check .
ruff check .
mypy src
pytest
python -m build --wheel --no-isolation
```

Every behavioral change should include a focused test. Changes affecting authorization, state mutation, latching, calibration, or audit behavior should explain the threat model and the compatibility impact in the pull-request description.

## Review expectations

Contributors must not commit credentials, tokens, generated caches, private data, or benchmark claims that cannot be reproduced. Public APIs should remain typed and documented. Security-sensitive behavior must fail closed, preserve the previous state on rejected proposals, and avoid including secret material in exceptions or audit records.

Use conventional commit-style subjects where practical, such as `fix: reject malformed boundary vectors`. Pull requests should state what changed, why it changed, how it was tested, and what risks remain.
