package console

import (
	"strings"

	"github.com/ergochat/readline"
)

// newCompleter builds the tab-completion tree for the console.
func (c *Console) newCompleter() *readline.PrefixCompleter {
	partOf := func(names ...string) []*readline.PrefixCompleter {
		out := make([]*readline.PrefixCompleter, 0, len(names))
		for _, n := range names {
			out = append(out, readline.PcItem(n))
		}
		return out
	}

	interfaceDynamic := func(line string) []string {
		fields := strings.Fields(line)
		// completes the word after `use interface`
		if len(fields) == 2 && fields[0] == "use" && fields[1] == "interface" {
			var names []string
			ifaces, err := c.app.Backend.DiscoverInterfaces()
			if err == nil {
				for _, iface := range ifaces {
					names = append(names, iface.Name)
				}
			}
			if c.iface != "" {
				names = append(names, c.iface)
			}
			return names
		}
		// completes an interface argument wherever a value is expected
		if strings.HasPrefix(line, "use interface") {
			return modesFor(c)
		}
		return nil
	}

	root := readline.NewPrefixCompleter(
		readline.PcItem("help", readline.PcItemDynamic(c.commandsMatching)),
		readline.PcItem("version"),
		readline.PcItem("status"),
		readline.PcItem("show", partOf("interfaces", "access-points", "aps", "stations", "clients", "observations")...),
		readline.PcItem("use", readline.PcItem("interface", readline.PcItemDynamic(interfaceDynamic))),
		readline.PcItem("back"),
		readline.PcItem("authorize"),
		readline.PcItem("sim", partOf("on", "off")...),
		readline.PcItem("run", readline.PcItem("--sim")),
		readline.PcItem("discover", readline.PcItem("--sim")),
		readline.PcItem("scan", partOf("--sim", "--ssid", "--bssid", "--band")...),
		readline.PcItem("enumerate", partOf("--sim", "--ssid", "--bssid", "--band")...),
		readline.PcItem("observe", readline.PcItem("--sim")),
		readline.PcItem("analyze", readline.PcItem("--session")),
		readline.PcItem("findings"),
		readline.PcItem("evidence"),
		readline.PcItem("report", partOf("--format", "--out")...),
		readline.PcItem("capabilities"),
		readline.PcItem("caps"),
		readline.PcItem("modules"),
		readline.PcItem("options"),
		readline.PcItem("target", partOf("show", "list")...),
		readline.PcItem("session"),
		readline.PcItem("events"),
		readline.PcItem("history"),
		readline.PcItem("clear"),
		readline.PcItem("banner"),
		readline.PcItem("logo"),
		readline.PcItem("completion", partOf("bash", "zsh", "fish", "powershell")...),
		readline.PcItem("updates"),
		readline.PcItem("update"),
		readline.PcItem("quit"),
		readline.PcItem("exit"),
		readline.PcItem("q"),
	)
	return root
}

// commandsMatching is a dynamic completer that completes command names.
func (c *Console) commandsMatching(line string) []string {
	var names []string
	prefix := strings.ToLower(strings.TrimSpace(line))
	if prefix == "" {
		for name := range c.cmds {
			if name == "quit" {
				continue
			}
			names = append(names, name)
		}
		return names
	}
	for name := range c.cmds {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}

// suggest returns the closest command name to word, or "".
func (c *Console) suggest(word string) string {
	best, bestDist := "", 1<<30
	for name := range c.cmds {
		if d := levenshtein(word, name); d < bestDist {
			bestDist = d
			best = name
		}
	}
	if bestDist <= max(2, len(word)/3) {
		return best
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

func modesFor(c *Console) []string {
	var m []string
	if ifaces, err := c.app.Backend.DiscoverInterfaces(); err == nil {
		for _, iface := range ifaces {
			m = append(m, iface.Name)
		}
	}
	if len(m) == 0 && c.sim {
		m = append(m, "wlan0")
	}
	if c.iface != "" {
		m = append(m, c.iface)
	}
	return m
}
