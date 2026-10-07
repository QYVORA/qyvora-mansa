// Package operation defines operational profiles that control how modules
// execute based on OPSEC considerations.
package operation

import (
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Profile defines execution parameters for an operational profile. It controls
// rate limiting, jitter, parallelism, and noise level filtering to balance
// effectiveness against operational security.
type Profile struct {
	// Name is the profile identifier.
	Name string

	// Description explains the profile's intended use case.
	Description string

	// MaxNoiseLevel is the highest noise level this profile will execute.
	// Modules with noise levels above this threshold are excluded from runs.
	MaxNoiseLevel models.NoiseLevel

	// RateLimit is the minimum interval between successive transmissions or
	// active operations. Zero means no artificial delay.
	RateLimit time.Duration

	// Jitter adds randomization to rate limiting to avoid predictable patterns.
	// The actual delay is RateLimit + random(0, Jitter).
	Jitter time.Duration

	// MaxParallel limits how many modules can run concurrently. Zero means
	// no parallelism (sequential execution only).
	MaxParallel int

	// PreferSimulation suggests using simulation mode when available to
	// minimize operational footprint.
	PreferSimulation bool
}

// StealthProfile prioritizes operational security and minimal detectability.
// It restricts execution to passive and low-noise operations, adds significant
// rate limiting and jitter, and prefers simulation when available.
var StealthProfile = Profile{
	Name:             "stealth",
	Description:      "Minimize operational footprint: passive/low noise only, rate-limited, sequential execution",
	MaxNoiseLevel:    models.NoiseLevelLow,
	RateLimit:        5 * time.Second,
	Jitter:           3 * time.Second,
	MaxParallel:      0, // Sequential only
	PreferSimulation: true,
}

// StandardProfile balances effectiveness and operational security. It allows
// moderate noise operations, applies modest rate limiting, and permits limited
// parallelism for efficiency.
var StandardProfile = Profile{
	Name:             "standard",
	Description:      "Balanced approach: moderate noise allowed, modest rate limiting, limited parallelism",
	MaxNoiseLevel:    models.NoiseLevelModerate,
	RateLimit:        1 * time.Second,
	Jitter:           500 * time.Millisecond,
	MaxParallel:      3,
	PreferSimulation: false,
}

// AggressiveProfile prioritizes assessment completeness over operational
// security. It allows all noise levels including aggressive operations, applies
// minimal rate limiting, and maximizes parallelism.
var AggressiveProfile = Profile{
	Name:             "aggressive",
	Description:      "Maximum effectiveness: all noise levels, minimal delays, full parallelism",
	MaxNoiseLevel:    models.NoiseLevelAggressive,
	RateLimit:        100 * time.Millisecond,
	Jitter:           50 * time.Millisecond,
	MaxParallel:      10,
	PreferSimulation: false,
}

// ProfileByName returns the named operational profile, or nil if not found.
func ProfileByName(name string) *Profile {
	switch name {
	case "stealth":
		return &StealthProfile
	case "standard":
		return &StandardProfile
	case "aggressive":
		return &AggressiveProfile
	default:
		return nil
	}
}

// AllProfiles returns all available operational profiles.
func AllProfiles() []Profile {
	return []Profile{StealthProfile, StandardProfile, AggressiveProfile}
}

// Allows reports whether a module with the given noise level may execute under
// this profile.
func (p Profile) Allows(noiseLevel models.NoiseLevel) bool {
	// Noise levels are ordered: passive < low < moderate < aggressive
	// If the module's noise level is within the profile's maximum, allow it.
	return noiseLevel <= p.MaxNoiseLevel
}

// FilterModules returns only the modules from the given list that are allowed
// under this profile's noise level constraints.
func (p Profile) FilterModules(metas []Meta) []Meta {
	allowed := make([]Meta, 0, len(metas))
	for _, meta := range metas {
		if p.Allows(meta.NoiseLevel) {
			allowed = append(allowed, meta)
		}
	}
	return allowed
}
