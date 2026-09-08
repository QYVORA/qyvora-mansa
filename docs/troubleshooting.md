# Troubleshooting

## Build errors: "error obtaining VCS status: exit status 128"

This happens when working outside a git checkout. Build, vet, and test
with VCS status disabled:

```sh
go build -buildvcs=false ./...
go vet -buildvcs=false ./...
go test -buildvcs=false ./...
```

## "no session available" / "no session found"

An analysis, findings, or report command requires an existing session.

```sh
# 1. Collect data first (simulated, no hardware needed)
mansa scan --sim
# 2. Now analysis commands have data to work with
mansa analyze
mansa findings
mansa report -f markdown
```

## Live scan requires root / permissions

Linux live scans use `iw`. Ensure:

```sh
which iw            # must be installed
sudo mansa scan -y  # or grant CAP_NET_ADMIN + CAP_NET_RAW
```

When hardware or permissions are unavailable, use `--sim`.

## Authorization prompt blocks a live command

Live (non-sim) commands require an explicit authorization confirmation:

```sh
mansa scan -y            # confirm authorization for this run
mansa assess -y          # full pipeline, authorized
```

## Update will not install (permission denied)

The self-update replaces the binary at `$GOBIN` or `~/go/bin`. If a
permission error occurs, Mansa prints:

```
try: sudo chown $(whoami) <binary> && chmod +x <binary>
```

## Report written to the wrong place

The `report` command uses `--out` to redirect to a file. Without
`--out`, output goes to stdout. To capture terminal output to a file:

```sh
mansa report -f markdown > report.md
```

## Checksum verification fails during self-update

The downloaded binary is compared against the release `checksums.txt`.
A mismatch aborts the update and leaves the existing binary untouched.
Usually this indicates a stale release asset; force an upgrade after a
new release is published.

## "unknown command" from the console

The console command set is fixed at build time. Run `help` inside the
console to list valid commands.

## Colors missing in terminal

Mansa disables ANSI color when stdout is not a TTY or when `NO_COLOR`
is set. Unset `NO_COLOR` or run in an interactive terminal to restore
teal headings.

Next: [FAQ](faq.md).