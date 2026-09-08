# Installation

## From source

Requires Go 1.22 or later (the module is built and tested with Go 1.26).

```sh
git clone https://github.com/QYVORA/qyvora-mansa.git
cd qyvora-mansa
make build          # produces bin/mansa
sudo make install   # installs binary, icon, and desktop entry under /usr/local
```

A user-local install does not need root:

```sh
make install-user   # ~/.local/bin + ~/.local/share/{applications,icons,pixmaps}
```

## Install script

The cross-platform installers fetch the latest release from GitHub and
verify it against the release checksums:

```sh
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-mansa/main/install.sh | sh
```

On Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/QYVORA/qyvora-mansa/main/install.ps1 | iex
```

## Self-update

Once installed, `mansa updates` checks for a newer release on GitHub.

```sh
mansa updates info     # check but do not install
mansa updates install  # download, verify SHA-256, and replace the binary
```

The downloaded artifact is verified against the `checksums.txt` of the
release before it replaces the current executable. On a permission
failure, Mansa prints an ownership hint (see `internal/selfupdate`).

> Binaries are placed under the user's `GOBIN` when set, otherwise
> `~/go/bin`, so self-update does not require root.

## Platform notes

- **Linux** is fully supported, including `make install` desktop
  integration.
- **macOS** builds from source; wireless scan uses the live backend when
  available and falls back cleanly otherwise.
- **Windows** builds from source; use `install.ps1` for binary installs.

## Verifying a build

```sh
make verify    # gofmt clean, vet, race tests, build
```

Next: [Quickstart](quickstart.md).