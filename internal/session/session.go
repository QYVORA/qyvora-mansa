// Package session provides the on-disk session store for Mansa.
// Sessions are saved as <id>.session.json files in a configured directory.
// "latest" resolves to the file with the newest modification time.
package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// DefaultDir is the fallback session directory.
var DefaultDir = filepath.Join(".", "sessions")

// Store manages session persistence.
type Store struct{ dir string }

// NewStore returns a session store rooted at dir (or DefaultDir).
func NewStore(dir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	return &Store{dir: dir}
}

// Dir returns the store directory.
func (s *Store) Dir() string { return s.dir }

// Save persists a session to disk and returns the file path.
func (s *Store) Save(sess *models.Session) (string, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(s.dir, sess.ID+".session.json")
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Load reads a session by id (or literal path if it ends in .session.json).
func (s *Store) Load(id string) (*models.Session, error) {
	path := id
	if !strings.HasSuffix(id, ".session.json") {
		path = filepath.Join(s.dir, id+".session.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sess models.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// List returns session IDs sorted newest-first by modification time.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type entry struct {
		id  string
		mod int64
	}
	var items []entry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".session.json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".session.json")
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, entry{id: id, mod: info.ModTime().UnixNano()})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].mod != items[j].mod {
			return items[i].mod > items[j].mod
		}
		return items[i].id < items[j].id
	})
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.id
	}
	return ids, nil
}

// Latest loads the most recent session, or an error if none exist.
func (s *Store) Latest() (*models.Session, error) {
	ids, err := s.List()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, os.ErrNotExist
	}
	return s.Load(ids[0])
}
