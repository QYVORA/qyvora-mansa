// Package selfupdate provides secure self-update capabilities for Mansa.
// It checks GitHub releases, verifies checksums, and performs atomic
// binary replacement.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config configures self-update behavior.
type Config struct {
	Owner          string
	Repo           string
	ToolName       string
	CurrentVersion func() string
}

// Status indicates the update check result.
type Status string

const (
	StatusUpdated        Status = "updated"
	StatusCurrent        Status = "current"
	StatusNewerInstalled Status = "newer_installed"
)

// Result holds the outcome of a self-update operation.
type Result struct {
	Status  Status `json:"status"`
	Current string `json:"current"`
	Latest  string `json:"latest,omitempty"`
	Path    string `json:"path,omitempty"`
	Error   string `json:"error,omitempty"`
}

// release is a simplified GitHub release.
type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// Run checks for updates and installs if available.
func Run(ctx context.Context, cfg Config, out io.Writer) Result {
	current := cfg.CurrentVersion()
	if current == "" || current == "dev" || current == "unknown" {
		return Result{Status: StatusCurrent, Current: current, Error: "cannot update from development build"}
	}
	rel, err := fetchLatest(ctx, cfg)
	if err != nil {
		return Result{Status: StatusCurrent, Current: current, Error: fmt.Sprintf("failed to check releases: %v", err)}
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	if CompareVersions(latest, current) <= 0 {
		return Result{Status: StatusCurrent, Current: current, Latest: latest}
	}
	if out != nil {
		fmt.Fprintf(out, "Updating from %s to %s...\n", current, latest)
	}
	exePath, err := os.Executable()
	if err != nil {
		return Result{Status: StatusCurrent, Current: current, Latest: latest, Error: "cannot determine executable path"}
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	artifactName := cfg.ToolName + "-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "darwin" {
		artifactName = cfg.ToolName + "-macos-" + runtime.GOARCH
	}
	if runtime.GOOS == "windows" {
		artifactName += ".exe"
	}
	var downloadURL string
	for _, a := range rel.Assets {
		if a.Name == artifactName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return Result{Status: StatusCurrent, Current: current, Latest: latest, Error: "no matching release asset"}
	}
	tmp := exePath + ".update-part"
	defer func() { _ = os.Remove(tmp) }()
	resp, err := httpGet(ctx, downloadURL)
	if err != nil {
		return Result{Status: StatusCurrent, Current: current, Latest: latest, Error: fmt.Sprintf("download failed: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return Result{Status: StatusCurrent, Current: current, Latest: latest, Error: "cannot create temp file"}
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return Result{Status: StatusCurrent, Current: current, Latest: latest, Error: "download interrupted"}
	}
	_ = f.Close()
	if err := verifyChecksum(ctx, cfg, artifactName, tmp); err != nil {
		_ = os.Remove(tmp)
		return Result{Status: StatusCurrent, Current: current, Latest: latest, Error: fmt.Sprintf("checksum verification failed: %v", err)}
	}
	if err := os.Rename(tmp, exePath); err != nil {
		_ = os.Remove(tmp)
		return Result{Status: StatusCurrent, Current: current, Latest: latest, Error: "failed to replace executable"}
	}
	return Result{Status: StatusUpdated, Current: current, Latest: latest, Path: exePath}
}

func fetchLatest(ctx context.Context, cfg Config) (*release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", cfg.Owner, cfg.Repo)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func verifyChecksum(ctx context.Context, cfg Config, artifactName, path string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", cfg.Owner, cfg.Repo)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return err
	}
	for _, a := range rel.Assets {
		if a.Name != "checksums.txt" {
			continue
		}
		creq, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.BrowserDownloadURL, nil)
		cresp, err := client.Do(creq)
		if err != nil {
			return err
		}
		defer cresp.Body.Close()
		body, err := io.ReadAll(cresp.Body)
		if err != nil {
			return err
		}
		expected := ""
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == artifactName {
				expected = fields[0]
				break
			}
		}
		if expected == "" {
			return fmt.Errorf("no checksum entry for %s in checksums.txt", artifactName)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, expected) {
			return fmt.Errorf("checksum mismatch: got %s, want %s", got, expected)
		}
		return nil
	}
	return fmt.Errorf("checksums.txt asset not found in release")
}

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return (&http.Client{Timeout: 10 * time.Minute}).Do(req)
}

// CompareVersions compares semver-like versions numerically.
// Returns >0 if a is newer, 0 if equal, <0 if b is newer.
func CompareVersions(a, b string) int {
	av := parseVersion(a)
	bv := parseVersion(b)
	for i := 0; i < len(av) && i < len(bv); i++ {
		if av[i] > bv[i] {
			return 1
		}
		if av[i] < bv[i] {
			return -1
		}
	}
	if cmp := len(av) - len(bv); cmp != 0 {
		return cmp
	}
	// Same numeric core: a pre-release (dash) sorts below a release.
	// Build metadata ("+meta") does not affect precedence.
	switch {
	case hasPrerelease(a) && !hasPrerelease(b):
		return -1
	case !hasPrerelease(a) && hasPrerelease(b):
		return 1
	}
	return 0
}

// parseVersion splits a version into its numeric components in order.
func parseVersion(v string) []int {
	v = strings.TrimPrefix(v, "v")
	core := v
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		core = v[:i]
	}
	nums := make([]int, 0, strings.Count(core, ".")+1)
	for _, p := range strings.Split(core, ".") {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		nums = append(nums, n)
	}
	return nums
}

func hasPrerelease(v string) bool {
	v = strings.TrimPrefix(v, "v")
	return strings.ContainsRune(v, '-')
}

// PermissionHint returns a user-friendly hint when a permission error occurs.
func PermissionHint(tool, path string) string {
	_ = tool
	return fmt.Sprintf("try: sudo chown $(whoami) %s && chmod +x %s", path, path)
}
