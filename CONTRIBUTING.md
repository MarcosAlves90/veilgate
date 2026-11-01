# Contributing to VeilGate

VeilGate is a small local privacy proxy. Contributions should preserve its
loopback-only boundary, reject unsupported request formats, and avoid recording
prompt contents or credentials.

## Before opening a change

Open an issue describing the problem or proposed behavior for significant work.
For bugs, provide the smallest reproducible example using **synthetic data**.
Never include live prompts, secrets, authorization headers, or personal data in
issues, pull requests, logs, or test fixtures. See [SECURITY.md](SECURITY.md) for
sensitive vulnerability reports.

## Local checks

Use Python 3.11 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python scripts/validate.py test
python scripts/validate.py coverage
```

On Windows, activate the virtual environment using its `Scripts` directory.
The tests exercise a local mock upstream; they do not contact real model APIs.

POLIS is optional for contributors. Maintainers can run `polis plan --repo .`
and `polis gates --repo .` against the committed `.polis/policy.json` policy.
The coverage gate requires the optional `dev` dependencies above.

## Pull requests

Keep changes focused; describe the behavior, evidence, security implications,
and remaining limitations. Add regression tests for privacy or routing defects.
Preserve backward compatibility with supported Chat Completions clients or
explain the reason for a change. All contributions are offered under the
repository's [MIT license](LICENSE).
