package cli

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// walk collects every command name reachable in the tree, at every depth, along
// with the depth it was found at.
func walk(c *cobra.Command, depth int, out map[string]int) {
	for _, sub := range c.Commands() {
		if sub.Hidden {
			continue
		}
		name := sub.Name()
		if name == "" || name == "help" || name == "completion" {
			continue
		}
		if _, seen := out[name]; !seen {
			out[name] = depth
		}
		walk(sub, depth+1, out)
	}
}

// commandNames returns the top-level names the shared TUI will offer.
func commandNames(root *cobra.Command) []string {
	names := map[string]int{}
	walk(root, 0, names)
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	return out
}

// subNames returns the completion tokens a command offers for its first
// argument, which is what the TUI completes after the parent name.
func subNames(c *cobra.Command) []string {
	var out []string
	for _, sub := range c.Commands() {
		if sub.Hidden {
			continue
		}
		if name := sub.Name(); name != "" && name != "help" && name != "completion" {
			out = append(out, name)
		}
	}
	return out
}

// classForVerb maps a CLI verb back to the operation class it runs.
func classForVerb(verb string) models.OperationClass {
	switch verb {
	case "validate":
		return models.ClassValidation
	case "test":
		return models.ClassActiveTest
	case "exploit":
		return models.ClassExploitation
	default:
		return models.OperationClass(verb)
	}
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

// Every published capability must be reachable by name from the TUI. A tool the
// console cannot name is a tool the console does not offer, however it behaves
// when typed by hand.
func TestEveryCapabilityCommandReachesTheTUI(t *testing.T) {
	root := newRootCmd()
	names := commandNames(root)

	for _, want := range []string{
		// Top-level surfaces.
		"tui", "discover", "scan", "enumerate", "observe", "analyze",
		"assess", "findings", "evidence", "report", "target", "session", "events",
		"capture", "credentials", "bluetooth", "capabilities", "version", "updates",
		// The three operation classes.
		"validate", "test", "exploit",
	} {
		if !contains(names, want) {
			t.Errorf("the TUI does not offer %q", want)
		}
	}
}

// An alias is declared on the Cobra command but is not a separate node in the
// tree, so the TUI offers the canonical name only. This checks the half Mansa
// controls: that the alias exists and resolves to the same command.
func TestTUIAliasResolvesToTheSameCommand(t *testing.T) {
	root := newRootCmd()
	for _, sub := range root.Commands() {
		if sub.Name() != "tui" {
			continue
		}
		if !contains(sub.Aliases, "console") {
			t.Errorf("tui does not declare the console alias, got %v", sub.Aliases)
		}
		return
	}
	t.Fatal("tui is not registered")
}

// Every operation module must appear as a completion token under its class, so
// an operator can discover and tab-complete a module instead of having to know
// its identifier already. A module offered only as a positional argument runs
// but cannot be found.
func TestEveryOperationModuleIsCompletable(t *testing.T) {
	root := newRootCmd()

	for _, verb := range []string{"validate", "test", "exploit"} {
		var parent *cobra.Command
		for _, sub := range root.Commands() {
			if sub.Name() == verb {
				parent = sub
				break
			}
		}
		if parent == nil {
			t.Fatalf("%s is not registered", verb)
		}
		subs := subNames(parent)
		for _, meta := range operationRegistry().ByClass(classForVerb(verb)) {
			if !contains(subs, meta.ID) {
				t.Errorf("%s does not offer %q for completion", verb, meta.ID)
			}
			// The token must carry a description, or completing it tells the
			// operator nothing about what it would run.
			for _, sub := range parent.Commands() {
				if sub.Name() == meta.ID && sub.Short == "" {
					t.Errorf("%s %s has no description for the completion list", verb, meta.ID)
				}
			}
		}
		if !contains(subs, "list") {
			t.Errorf("%s does not offer the list subcommand", verb)
		}
	}
}

// A module must run the same way whether it is named as a subcommand or typed
// as a positional argument. Both paths have to reach one implementation, or the
// two surfaces can drift into testing different things.
func TestModuleRunsByNameAndByArgument(t *testing.T) {
	root := newRootCmd()
	for _, verb := range []string{"validate", "test", "exploit"} {
		var parent *cobra.Command
		for _, sub := range root.Commands() {
			if sub.Name() == verb {
				parent = sub
				break
			}
		}
		if parent == nil {
			t.Fatalf("%s is not registered", verb)
		}
		for _, meta := range operationRegistry().ByClass(classForVerb(verb)) {
			var named *cobra.Command
			for _, sub := range parent.Commands() {
				if sub.Name() == meta.ID {
					named = sub
				}
			}
			if named == nil {
				t.Errorf("%s %s is not registered as a subcommand", verb, meta.ID)
				continue
			}
			if named.Short == "" {
				t.Errorf("%s %s has an empty short description", verb, meta.ID)
			}
		}
	}
}

// The capabilities the TUI shows in its F1 view come from the same registry the
// contract publishes, so the two cannot describe different sets of tools.
func TestTUIAndContractShareOneCapabilitySource(t *testing.T) {
	resetTestApp(t)
	registry := appState.Capabilities()
	if len(registry) == 0 {
		t.Fatal("the capability registry is empty")
	}
	byID := map[string]bool{}
	for _, tool := range registry {
		byID[tool.ID] = true
	}
	// Every operation module must be in the registry the TUI reads.
	for _, meta := range operationRegistry().List() {
		want := "mansa." + operationVerb(meta.Class) + "." + meta.ID
		if !byID[want] {
			t.Errorf("module %s is not published as capability %q", meta.ID, want)
		}
	}
}
