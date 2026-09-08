// Package models defines the core domain types shared across all Mansa
// packages. Every serializable entity lives here; internal packages only
// orchestrate and render.
package models

import "time"

// TargetType enumerates the scope of an assessment.
type TargetType string

const (
	TargetInterface TargetType = "interface"
	TargetSSID      TargetType = "ssid"
	TargetBSSID     TargetType = "bssid"
	TargetSession   TargetType = "session"
	TargetCapture   TargetType = "capture"
)

// Authorization records that a human explicitly granted scope.
type Authorization struct {
	Granted   bool      `json:"granted"`
	GrantedAt time.Time `json:"granted_at,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Method    string    `json:"method,omitempty"`
	GrantedBy string    `json:"granted_by,omitempty"`
}

// Target is the declared scope of an assessment.
type Target struct {
	ID            string        `json:"id"`
	Type          TargetType    `json:"type"`
	Value         string        `json:"value"`
	Interface     string        `json:"interface,omitempty"`
	Authorization Authorization `json:"authorization"`
	Profile       string        `json:"profile,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

// Authorized reports whether this target has been granted access.
func (t *Target) Authorized() bool { return t != nil && t.Authorization.Granted }

// DisplayName returns a human-readable target label.
func (t *Target) DisplayName() string {
	if t == nil {
		return ""
	}
	if t.Value != "" {
		return string(t.Type) + ":" + t.Value
	}
	return string(t.Type) + ":all"
}
