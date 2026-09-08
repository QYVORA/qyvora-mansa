# Security Policy

Mansa is a **authorized-use-only** wireless assessment framework. We
take the security of the tool and of its users seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.
Instead, report privately to the maintainers via a GitHub security
advisory or a direct email to the project maintainers.

Please include:

- The affected version (`mansa version`)
- A description of the vulnerability
- Steps to reproduce
- Impact and, if known, a suggested fix

You should receive an acknowledgement within 5 business days and a
detailed response (including a workaround if applicable) within 10
business days.

## Scope

- The Mansa binaries and source
- The self-update mechanism (checksum verification)
- The event stream, session store, and report generation
- The authorization gate (live non-sim operations)

## Authorized use

Mansa enforces an explicit authorization step before live (`--sim` is
exempt) assessment. Review [docs/authorization.md](docs/authorization.md)
so you understand the model and its limitations. Using Mansa against
networks you do not own or do not have authorization to evaluate may be
unlawful in many jurisdictions.

## Self-update integrity

Released binaries are verified against a SHA-256 `checksums.txt`
manifest before replacement. If a checksum mismatch is ever detected,
the update aborts and the existing binary is left untouched.

## Secure development

- All changes are covered by the test suite in CI (`make verify`).
- Analysis rules are pure and deterministic.
- Dependencies are pinned in `go.mod`/`go.sum`.