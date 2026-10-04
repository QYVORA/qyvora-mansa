package operation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Request is a resolved request to run one module. It is what the CLI builds
// from flags and what the executor gates.
type Request struct {
	// ModuleID names the module to run.
	ModuleID string

	// Class is the verb the run was asked for. It must match the module's own
	// class: running a validation module under `exploit` would apply the
	// exploit gates to it and the validation gates to nothing.
	Class models.OperationClass

	// Target is the authorized scope. Required: a run without a target is
	// refused before anything else happens.
	Target *models.Target

	// Interface is the wireless interface the operation uses.
	Interface string

	// Session supplies collected observations and receives the record.
	Session *models.Session

	// Params are the module inputs, keyed by declared parameter name.
	Params map[string]string

	// Operator is the identity recorded as responsible for the run.
	Operator string

	// Simulated runs the module's simulation path. No over-air action is taken.
	Simulated bool

	// DryRun plans the run and reports it without transmitting or collecting.
	DryRun bool

	// Database is a saved GATT attribute table path.
	Database string
}

// Param returns a parameter value, falling back to the module's declared
// default. An absent parameter and an empty one are the same thing to a module,
// so they resolve identically.
func (r Request) Param(module Meta, name string) string {
	if value, ok := r.Params[name]; ok && value != "" {
		return value
	}
	if parameter, ok := module.Parameter(name); ok {
		return parameter.Default
	}
	return ""
}

// IntParam returns a parameter as an integer, and refuses a value that is not
// one. A silently defaulted count would run a different test than the operator
// asked for, which is the specific failure the bounds exist to prevent.
func (r Request) IntParam(module Meta, name string) (int, error) {
	raw := r.Param(module, name)
	if raw == "" {
		return 0, fmt.Errorf("parameter %q has no value and no default", name)
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parameter %q must be a whole number, got %q", name, raw)
	}
	return value, nil
}

// DurationParam returns a parameter as a duration, and refuses a value outside
// the module's declared ceiling.
func (r Request) DurationParam(module Meta, name string, ceiling time.Duration) (time.Duration, error) {
	raw := r.Param(module, name)
	if raw == "" {
		return 0, fmt.Errorf("parameter %q has no value and no default", name)
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parameter %q must be a duration such as 2s, got %q", name, raw)
	}
	if value <= 0 {
		return 0, fmt.Errorf("parameter %q must be positive, got %q", name, raw)
	}
	if ceiling > 0 && value > ceiling {
		return 0, fmt.Errorf("parameter %q is %s, above the %s ceiling", name, value, ceiling)
	}
	return value, nil
}

// BoolParam reports whether a boolean parameter is set. A valueless flag-style
// parameter (`--param lab`) arrives as an empty string, which means true: the
// operator named it, and its presence is the whole point.
func (r Request) BoolParam(module Meta, name string) bool {
	value, ok := r.Params[name]
	if !ok {
		return false
	}
	if value == "" {
		return true
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return true
	}
	return parsed
}

// unknownParams returns the parameter names a request supplied that the module
// does not declare.
//
// They are reported rather than ignored. A typo in --param would otherwise
// silently drop the one input that scoped the run to an authorized station,
// and the run would proceed with a default that reaches further than intended.
func (r Request) unknownParams(module Meta) []string {
	var out []string
	for name := range r.Params {
		if _, ok := module.Parameter(name); !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// missingParams returns the declared required parameters the request omits.
//
// A boolean parameter is satisfied by being named. `--param lab` carries no
// value, and BoolParam reads that as set, so treating the empty value as missing
// here would make a required acknowledgement impossible to supply.
func (r Request) missingParams(module Meta) []string {
	var out []string
	for _, parameter := range module.Parameters {
		if !parameter.Required {
			continue
		}
		value, ok := r.Params[parameter.Name]
		if !ok {
			out = append(out, parameter.Name)
			continue
		}
		if parameter.Kind == "bool" {
			continue
		}
		if strings.TrimSpace(value) == "" {
			out = append(out, parameter.Name)
		}
	}
	sort.Strings(out)
	return out
}
