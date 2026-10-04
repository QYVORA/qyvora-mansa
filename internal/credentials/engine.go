// Package credentials implements a bounded streaming candidate pipeline.
// Protocol-specific verification is supplied explicitly and results require evidence.
package credentials

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxWordLength = 1 << 20

var ErrCandidateLimit = errors.New("candidate limit reached")

type Mutation struct{ Prefix, Suffix string }
type Config struct {
	Builtin       bool
	Wordlists     []string
	WordlistDir   string
	Generated     []string
	Mutations     []Mutation
	MaxCandidates uint64
	Filter        func(string) bool
}
type Verification struct {
	Matched  bool
	Evidence []string
}
type Verifier interface {
	Verify(context.Context, *models.Target, string) (Verification, error)
}
type Progress struct {
	Processed uint64
	Source    string
}
type ProgressFunc func(Progress)
type Result struct {
	Verified        bool     `json:"verified"`
	CandidateSHA256 string   `json:"candidate_sha256"`
	Source          string   `json:"source"`
	Evidence        []string `json:"evidence"`
}
type candidate struct{ value, source string }
type lineReader struct {
	file *os.File
	scan *bufio.Scanner
	path string
	line uint64
}

func openWordlist(path string) (*lineReader, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, fmt.Errorf("open wordlist %s: %w", path, e)
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), maxWordLength)
	return &lineReader{file: f, scan: s, path: path}, nil
}
func (r *lineReader) next(ctx context.Context) (candidate, bool, error) {
	for r.scan.Scan() {
		if e := ctx.Err(); e != nil {
			return candidate{}, false, e
		}
		r.line++
		v := strings.TrimSuffix(r.scan.Text(), "\r")
		if v != "" {
			return candidate{v, fmt.Sprintf("%s:%d", r.path, r.line)}, true, nil
		}
	}
	if e := r.scan.Err(); e != nil {
		return candidate{}, false, fmt.Errorf("read wordlist %s: %w", r.path, e)
	}
	return candidate{}, false, nil
}

// Run streams built-in, external, and generated candidates in deterministic order.
// It never exposes the candidate value in results and rejects unauthorised targets.
func Run(ctx context.Context, target *models.Target, cfg Config, verifier Verifier, progress ProgressFunc) (*Result, error) {
	if target == nil || !target.Authorized() {
		return nil, errors.New("credential assessment requires explicit target authorization")
	}
	if verifier == nil {
		return nil, errors.New("credential verifier is not configured")
	}
	if cfg.MaxCandidates == 0 {
		return nil, errors.New("a positive candidate limit is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	paths := append([]string(nil), cfg.Wordlists...)
	if cfg.WordlistDir != "" {
		entries, e := os.ReadDir(cfg.WordlistDir)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			if entry.Type().IsRegular() {
				paths = append(paths, filepath.Join(cfg.WordlistDir, entry.Name()))
			}
		}
	}
	sort.Strings(paths)
	readers := make([]*lineReader, 0, len(paths))
	for _, path := range paths {
		r, e := openWordlist(path)
		if e != nil {
			for _, opened := range readers {
				_ = opened.file.Close()
			}
			return nil, e
		}
		readers = append(readers, r)
	}
	defer func() {
		for _, r := range readers {
			_ = r.file.Close()
		}
	}()
	var count uint64
	verify := func(value, source string) (*Result, bool, error) {
		if e := ctx.Err(); e != nil {
			return nil, false, e
		}
		if cfg.Filter != nil && !cfg.Filter(value) {
			return nil, false, nil
		}
		if count >= cfg.MaxCandidates {
			return nil, false, ErrCandidateLimit
		}
		count++
		if progress != nil {
			progress(Progress{count, source})
		}
		v, e := verifier.Verify(ctx, target, value)
		if e != nil {
			return nil, false, fmt.Errorf("verify candidate %d: %w", count, e)
		}
		if !v.Matched {
			return nil, false, nil
		}
		if len(v.Evidence) == 0 {
			return nil, false, errors.New("verifier reported a match without evidence")
		}
		sum := sha256.Sum256([]byte(value))
		return &Result{true, hex.EncodeToString(sum[:]), source, append([]string(nil), v.Evidence...)}, true, nil
	}
	try := func(item candidate) (*Result, bool, error) {
		if r, ok, e := verify(item.value, item.source); e != nil || ok {
			return r, ok, e
		}
		for i, m := range cfg.Mutations {
			v := m.Prefix + item.value + m.Suffix
			if r, ok, e := verify(v, fmt.Sprintf("%s#mutation-%d", item.source, i+1)); e != nil || ok {
				return r, ok, e
			}
		}
		return nil, false, nil
	}
	if cfg.Builtin {
		for _, v := range builtin {
			if r, ok, e := try(candidate{v, "mansa-builtin-v1"}); e != nil || ok {
				return r, e
			}
		}
	}
	for _, reader := range readers {
		for {
			item, ok, e := reader.next(ctx)
			if e != nil {
				return nil, e
			}
			if !ok {
				break
			}
			if r, matched, e := try(item); e != nil || matched {
				return r, e
			}
		}
	}
	for i, v := range cfg.Generated {
		if r, ok, e := try(candidate{v, fmt.Sprintf("generated:%d", i+1)}); e != nil || ok {
			return r, e
		}
	}
	return nil, nil
}

var builtin = []string{"mansa-lab", "wireless-lab", "qyvora-lab", "changeme", "password", "password123", "admin123", "letmein", "welcome123", "correct-horse-battery-staple"}
