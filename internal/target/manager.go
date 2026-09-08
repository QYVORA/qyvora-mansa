// Package target provides persistent target management for Mansa.
package target

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// ErrUnauthorizedTarget is returned when trying to set an unauthorized target.
var ErrUnauthorizedTarget = fmt.Errorf("target is not authorized")

type state struct {
	CurrentID string           `json:"current_id,omitempty"`
	Targets   []*models.Target `json:"targets,omitempty"`
}

// Manager manages saved targets with on-disk persistence.
type Manager struct {
	mu      sync.RWMutex
	path    string
	current *models.Target
	byID    map[string]*models.Target
}

// NewManager creates a target manager backed by path.
func NewManager(path string) *Manager {
	m := &Manager{
		path: path,
		byID: make(map[string]*models.Target),
	}
	m.load()
	return m
}

// Set persists a new target (must be authorized).
func (m *Manager) Set(t *models.Target) error {
	if t == nil || !t.Authorized() {
		return ErrUnauthorizedTarget
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.ID == "" {
		t.ID = models.NewID("tgt")
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	m.current = t
	m.byID[t.ID] = t
	return m.save()
}

// Current returns the active target.
func (m *Manager) Current() *models.Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Get returns a target by id.
func (m *Manager) Get(id string) (*models.Target, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.byID[id]
	return t, ok
}

// List returns all saved targets.
func (m *Manager) List() []*models.Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*models.Target, 0, len(m.byID))
	for _, t := range m.byID {
		out = append(out, t)
	}
	return out
}

func (m *Manager) load() {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return
	}
	for _, t := range s.Targets {
		m.byID[t.ID] = t
	}
	if s.CurrentID != "" {
		m.current = m.byID[s.CurrentID]
	}
}

func (m *Manager) save() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	targets := make([]*models.Target, 0, len(m.byID))
	for _, t := range m.byID {
		targets = append(targets, t)
	}
	s := state{CurrentID: m.current.ID, Targets: targets}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0o600)
}
