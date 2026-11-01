# Security policy

VeilGate is a best-effort pattern-based privacy filter, **not** a guarantee of
anonymity. Read the [threat model](docs/threat-model.md) before relying on it.

## Supported versions

Security fixes target the current `main` branch. There is no commitment to
maintain older releases while the project is at version `0.1.0`.

## Reporting vulnerabilities

Do **not** post exploits containing real secrets, personal data, or private
prompts in public issues, discussions, or pull requests. Use the repository's
[Security advisories](https://github.com/MarcosAlves90/veilgate/security/advisories)
page and select **Report a vulnerability** to submit a private report to the
maintainer. If the reporting interface is unavailable, request an alternative
private contact channel through the maintainer's verified GitHub profile,
without disclosing vulnerability details publicly.

Include the affected commit/version, the security boundary crossed, and a
minimal reproduction with **fictitious data**. Do not test against someone
else's accounts or services. No response SLA, formal audit, or bug bounty is
currently offered.
