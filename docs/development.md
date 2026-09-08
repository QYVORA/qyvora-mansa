# Development

## Repository layout

```
qyvora-mansa/
├── main.go                    # entry point (calls internal/cli.Execute)
├── cmd/mansa/main.go          # duplicate entry point for `go install ./cmd/mansa`
├── internal/
│   ├── app/                   # shared application state for CLI + console
│   ├── banner/                # canonical brand art
│   ├── capabilities/          # capability contract
│   ├── cli/                   # cobra command tree, flags, exit codes
│   ├── config/                # layered config loading (YAML/env/defaults)
│   ├── console/               # interactive REPL + pipe mode
│   ├── errors/                # typed error helpers
│   ├── events/                # JSONL event stream
│   ├── evidence/              # evidence collection
│   ├── exitcode/              # exit-code constants
│   ├── findings/              # finding aggregation
│   ├── logger/                # leveled logger
│   ├── output/                # terminal/json/yaml/markdown/html renderers
│   ├── pipeline/              # 8-stage runner
│   ├── reporting/             # report rendering
│   ├── risk/                  # risk scoring
│   ├── rules/                 # rule engine + builtin rules
│   ├── selfupdate/            # semver compare + checksum-verified self-update
│   ├── session/               # on-disk session store
│   ├── table/                 # table renderer
│   ├── target/                # target management
│   ├── transport/             # Backend interface; simulation + linux-iw
│   ├── ui/                    # shared UI helpers (banner wiring)
│   ├── validation/            # data validation
│   ├── version/               # engine version (injected via ldflags)
│   └── wireless/              # OUI vendor lookup
├── pkg/models/                # canonical domain types
├── assets/                    # mansa.png, mansa.ico, mansa.desktop
├── configs/                   # config.yaml.example
├── docs/                      # documentation
└── .github/workflows/         # CI + release
```

## Building

```sh
make build          # go build with version ldflags into bin/mansa
```

The `internal/version.Version` value is injected by ldflags. When building
the binary yourself, the version is `dev` unless overridden:

```sh
make build VERSION=1.2.3
```

> Because the working directory may not be a git checkout, always pass
> `-buildvcs=false` to `go build`/`go vet`/`go test` in this environment
> to avoid VCS-status errors.

## Testing

```sh
make test           # go test ./... -count=1
make test-race      # go test -race ./...
make vet            # go vet ./...
make lint           # gofmt check + golangci-lint
make verify         # lint + vet + race tests + build
```

The test suite covers:

- The console command-line parser (flags, quoting, value consumption)
- The builtin WLAN rules (including WPA-vs-WPA2 exact matching)
- The deterministic simulation dataset
- The 8-stage pipeline (full, partial, and re-analysis runs)
- The session store (round-trip, latest, dedup)
- Risk scoring and level thresholds
- Config loading (defaults, overrides, env, malformed files)
- Semver comparison and self-update checksum verification
- The CLI root (exit codes, assess, missing-session behavior)

## Conventions

- **Exit codes**: `0` success, `1` runtime error, `2` usage error,
  `130` interrupted.
- **Domain types** live in `pkg/models`; internal packages only
  orchestrate and render.
- **Determinism**: rules are pure functions of the session data.
- **Authorization**: every live (non-sim) command is gated.
- **Brand**: teal `#00BAA3`; series font conventions in `internal/ui`.

## Adding a capability

Capabilities are declared as a static contract in
`internal/capabilities/`:

```sh
mansa capabilities -o json
```

Each capability carries an ID, description, output format, risk level,
amount of authorization required, and reversibility/state-change flags.
Keep the contract additive and versioned.

Next: [Contributing](contributing.md).