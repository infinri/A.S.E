# Security Policy

ASE is a security tool. Vulnerabilities in ASE itself could impact every store running it, so we treat them seriously.

## Supported Versions

Security fixes land on the latest minor release. Older minors are not patched.

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.** Public disclosure before a fix exists puts every ASE user at risk.

Email: **lucio.saldivar@infinri.com**

Subject line: `[ASE security] <short summary>`

Please include:

- A description of the issue and the impact you believe it has.
- Steps to reproduce, or a proof-of-concept if you have one.
- The commit SHA or release version you tested against.
- Any suggested remediation, if you have thoughts.

If you'd like to encrypt, request a PGP key in your first message and I'll reply with one.

## Response SLA

| Milestone              | Target               |
|------------------------|----------------------|
| Acknowledgment         | within 72 hours      |
| Initial triage + severity assessment | within 7 days |
| Fix released (high / critical) | within 30 days |
| Public disclosure      | coordinated, 90 days maximum from report |

Low-severity issues may take longer; you'll get a status update at least every 14 days until the issue is closed.

## Disclosure Policy

- **Coordinated disclosure.** A fix ships before public details.
- **Credit.** Reporters are credited in the release notes and `CHANGELOG.md` unless they prefer anonymity.
- **Maximum embargo: 90 days.** If a fix is not available by day 90, the issue is published with mitigation guidance so users can protect themselves.

## Out of Scope

- Vulnerabilities in third-party feeds ASE polls (CISA KEV, NVD, GHSA, OSV, Packagist) -- report those upstream.
- Vulnerabilities in third-party services (Slack) -- report to the service operator.
- Vulnerabilities requiring a compromised ASE host to exploit -- ASE runs with the privileges of the user who launched it; host security is out of scope.
- Missing hardening features that don't correspond to a concrete exploit path -- open a regular issue or PR instead.
