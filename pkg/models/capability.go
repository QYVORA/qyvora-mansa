package models

// Capability describes one atomic operation Mansa can perform.
type Capability struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Framework    string   `json:"framework"`
	Category     string   `json:"category"`
	Output       []string `json:"output,omitempty"`
	Risk         string   `json:"risk"`
	AuthRequired bool     `json:"authorization_required"`
	Confirm      bool     `json:"confirmation_required"`
	Reversible   bool     `json:"reversible"`
	ChangesState bool     `json:"changes_state"`
	Targets      []string `json:"target_types,omitempty"`
	Duration     string   `json:"duration,omitempty"`
}
