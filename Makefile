BINARY := mansa
VERSION ?= dev
GOFLAGS := -trimpath -ldflags="-s -w -X github.com/QYVORA/qyvora-mansa/internal/version.Version=$(VERSION)"

PREFIX ?= /usr/local
DESTDIR ?=

# --- install layout ------------------------------------------------------
# System-wide install (default PREFIX=/usr/local, typically needs root):
#   /usr/local/bin/mansa             command
#   /usr/local/share/applications/   desktop entry (searchable in the app menu)
#   /usr/local/share/icons/hicolor/512x512/apps/mansa.png
#   /usr/local/share/pixmaps/mansa.png
# User install (make install-user) mirrors the same layout under ~/.local.

ICON    := assets/mansa.png
DESKTOP := assets/mansa.desktop

BINDIR    := $(DESTDIR)$(PREFIX)/bin
ICONDIR   := $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps
PIXMAPDIR := $(DESTDIR)$(PREFIX)/share/pixmaps
APPDIR    := $(DESTDIR)$(PREFIX)/share/applications

USERBIN    := $(HOME)/.local/bin
USERICON   := $(HOME)/.local/share/icons/hicolor/512x512/apps
USERPIXMAP := $(HOME)/.local/share/pixmaps
USERAPP    := $(HOME)/.local/share/applications

.PHONY: all build install install-data install-user uninstall uninstall-user test test-race vet lint verify smoke clean

all: lint vet test build

build:
	go build $(GOFLAGS) -buildvcs=false -o bin/$(BINARY) .

test:
	go test -buildvcs=false ./... -count=1 -timeout 60s

test-race:
	go test -buildvcs=false -race ./... -count=1 -timeout 120s

vet:
	go vet -buildvcs=false ./...

lint:
	gofmt -l . | tee /dev/stderr | (! read -r _)   # fail if any file needs formatting
	golangci-lint run ./...

verify: lint vet test-race build
	@echo "ALL CHECKS PASSED"

smoke:
	bash tests/smoke.sh

install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	$(MAKE) install-data

install-data:
	install -d $(ICONDIR) $(PIXMAPDIR) $(APPDIR)
	install -m 0644 $(ICON) $(ICONDIR)/mansa.png
	install -m 0644 $(ICON) $(PIXMAPDIR)/mansa.png
	sed -e 's|@PREFIX@|$(PREFIX)|g' $(DESKTOP) > $(APPDIR)/mansa.desktop
	chmod 0644 $(APPDIR)/mansa.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true
	@echo "mansa installed to $(BINDIR) with icon and desktop entry."

install-user: build
	install -d $(USERBIN)
	install -m 0755 bin/$(BINARY) $(USERBIN)/$(BINARY)
	install -d $(USERICON) $(USERPIXMAP) $(USERAPP)
	install -m 0644 $(ICON) $(USERICON)/mansa.png
	install -m 0644 $(ICON) $(USERPIXMAP)/mansa.png
	sed -e 's|@PREFIX@|$(HOME)/.local|g' $(DESKTOP) > $(USERAPP)/mansa.desktop
	chmod 0644 $(USERAPP)/mansa.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true
	@echo "mansa installed to $(USERBIN) with icon and desktop entry."
	@echo "Add $$HOME/.local/bin to your PATH if it is not already there."

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(ICONDIR)/mansa.png $(PIXMAPDIR)/mansa.png $(APPDIR)/mansa.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true

uninstall-user:
	rm -f $(USERBIN)/$(BINARY)
	rm -f $(USERICON)/mansa.png $(USERPIXMAP)/mansa.png $(USERAPP)/mansa.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true

clean:
	rm -rf bin dist releases/
