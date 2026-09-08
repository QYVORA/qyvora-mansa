# Contributing

Thanks for your interest in contributing to Mansa.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md). By
participating you agree to abide by its terms.

## Getting started

1. Fork the repository and create a feature branch.
2. Set up the build and test tools (see [Development](docs/development.md)).
3. Make focused changes with tests.
4. Run `make verify` (gofmt, vet, race tests, build) before opening a PR.
5. Open a pull request with a clear description.

## Development

See [docs/development.md](docs/development.md) for the repository
layout, build commands, and conventions.

## Guidelines

- Follow the existing code conventions (see
  [docs/development.md](docs/development.md)).
- Domain types live in `pkg/models`; internal packages orchestrate and
  render.
- Keep analysis rules deterministic (pure functions of session data).
- Add tests for every new rule, command, or state transition.
- Keep the capability contract additive and versioned.
- Do not add comments to source code unless they carry real value.

## Commit messages

Use clear, imperative, conventional-style messages, e.g.
`add wlan-011 overlapping-channel rule`. Keep changes focused; one
logical change per commit.

## Pull requests

- Reference any related issue.
- Describe what the change does and why.
- Include test results.
- Keep the diff minimal and reviewable.

## Reporting bugs

Open an issue with:

- Mansa version (`mansa version`)
- OS and Go version
- Command run and exact error output
- Whether it reproduces in `--sim` mode

## Security disclosures

For vulnerabilities, see [SECURITY.md](SECURITY.md) instead of a public
issue.