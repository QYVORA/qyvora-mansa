package console

// Command is one console command.
type Command struct {
	Name     string
	Aliases  []string
	Category string
	Summary  string
	Usage    string
	Details  string
	Flags    []FlagSpec
	Run      func(c *Console, p *Parsed) error
}

const (
	catCore     = "CORE"
	catScan     = "SCAN"
	catAnalysis = "ANALYSIS"
	catSystem   = "SYSTEM"
)

var categoryOrder = []string{catCore, catScan, catAnalysis, catSystem}

func (cmd *Command) flagSpecs() map[string]FlagSpec {
	m := make(map[string]FlagSpec, len(cmd.Flags))
	for _, f := range cmd.Flags {
		m[f.Name] = f
	}
	return m
}

func (c *Console) registerCommands() {
	c.cmds = map[string]*Command{}
	c.aliases = map[string]string{}
	for _, cmd := range commandTable() {
		c.cmds[cmd.Name] = cmd
		for _, a := range cmd.Aliases {
			c.aliases[a] = cmd.Name
		}
	}
}

func commandTable() []*Command {
	return []*Command{
		{
			Name: "help", Aliases: []string{"?"}, Category: catCore,
			Summary: "show command help",
			Usage:   "help [command]",
			Details: "Without arguments lists every command. With a command name it shows that command's full help.",
			Run:     runHelp,
		},
		{
			Name: "version", Category: catCore,
			Summary: "print version information",
			Usage:   "version",
			Run:     runVersion,
		},
		{
			Name: "status", Category: catCore,
			Summary: "show current assessment state",
			Usage:   "status",
			Run:     runStatus,
		},
		{
			Name: "show", Category: catCore,
			Summary: "show discovery results (interfaces, aps, stations)",
			Usage:   "show <interfaces|access-points|aps|stations|clients|observations>",
			Details: "Shows results from the current or latest session.",
			Run:     runShow,
		},
		{
			Name: "use", Category: catScan,
			Summary: "select the assessment interface",
			Usage:   "use interface <name>",
			Details: "Selects a wireless interface for live assessment. Use `authorize` after selecting to grant scope.",
			Run:     runUse,
		},
		{
			Name: "back", Category: catScan,
			Summary: "clear the selected interface",
			Usage:   "back",
			Run:     runBack,
		},
		{
			Name: "authorize", Category: catCore,
			Summary: "grant authorization for live assessment scope",
			Usage:   "authorize",
			Details: "Interactive authorization for the currently selected interface. Simulation never requires it.",
			Run:     runAuthorize,
		},
		{
			Name: "sim", Category: catScan,
			Summary: "toggle offline simulation mode",
			Usage:   "sim [on|off]",
			Run:     runSim,
		},
		{
			Name: "run", Category: catScan,
			Summary: "run the full assessment pipeline",
			Usage:   "run [--sim]",
			Run:     runRun,
		},
		{
			Name: "discover", Category: catScan,
			Summary: "discover wireless interfaces",
			Usage:   "discover [--sim]",
			Flags:   []FlagSpec{{Name: "sim", Kind: FlagBool}},
			Run:     runDiscover,
		},
		{
			Name: "scan", Category: catScan,
			Summary: "scan for access points",
			Usage:   "scan [--sim] [--ssid X] [--bssid X] [--band X]",
			Flags: []FlagSpec{
				{Name: "sim", Kind: FlagBool},
				{Name: "ssid", Kind: FlagString},
				{Name: "bssid", Kind: FlagString},
				{Name: "band", Kind: FlagString},
			},
			Run: runScan,
		},
		{
			Name: "enumerate", Category: catScan,
			Summary: "enumerate access-point inventory",
			Usage:   "enumerate [--sim] [--ssid X] [--bssid X] [--band X]",
			Flags: []FlagSpec{
				{Name: "sim", Kind: FlagBool},
				{Name: "ssid", Kind: FlagString},
				{Name: "bssid", Kind: FlagString},
				{Name: "band", Kind: FlagString},
			},
			Run: runEnumerate,
		},
		{
			Name: "observe", Category: catScan,
			Summary: "observe stations and clients",
			Usage:   "observe [--sim]",
			Flags:   []FlagSpec{{Name: "sim", Kind: FlagBool}},
			Run:     runObserve,
		},
		{
			Name: "analyze", Category: catAnalysis,
			Summary: "analyze the latest session",
			Usage:   "analyze [--session <id>]",
			Flags:   []FlagSpec{{Name: "session", Kind: FlagString}},
			Run:     runAnalyze,
		},
		{
			Name: "findings", Category: catAnalysis,
			Summary: "show findings from a session",
			Usage:   "findings [session-id]",
			Run:     runFindings,
		},
		{
			Name: "evidence", Category: catAnalysis,
			Summary: "show evidence from a session",
			Usage:   "evidence [session-id]",
			Run:     runEvidence,
		},
		{
			Name: "report", Category: catAnalysis,
			Summary: "render a formatted report",
			Usage:   "report [--format <fmt>] [--out <path>]",
			Flags: []FlagSpec{
				{Name: "format", Kind: FlagString},
				{Name: "out", Kind: FlagString},
			},
			Run: runReport,
		},
		{
			Name: "capabilities", Aliases: []string{"caps"}, Category: catCore,
			Summary: "list machine-readable capabilities",
			Usage:   "capabilities",
			Run:     runCapabilities,
		},
		{
			Name: "modules", Category: catSystem,
			Summary: "list assessment modules",
			Usage:   "modules",
			Run:     runModules,
		},
		{
			Name: "options", Category: catSystem,
			Summary: "show current session options",
			Usage:   "options",
			Run:     runOptions,
		},
		{
			Name: "target", Category: catCore,
			Summary: "manage targets",
			Usage:   "target [show|list]",
			Run:     runTarget,
		},
		{
			Name: "session", Category: catSystem,
			Summary: "list or inspect sessions",
			Usage:   "session [id]",
			Run:     runSession,
		},
		{
			Name: "events", Category: catSystem,
			Summary: "show session stage events",
			Usage:   "events [session-id]",
			Run:     runEvents,
		},
		{
			Name: "history", Category: catSystem,
			Summary: "show command history",
			Usage:   "history",
			Run:     runHistory,
		},
		{
			Name: "clear", Category: catSystem,
			Summary: "clear the terminal",
			Usage:   "clear",
			Run:     runClear,
		},
		{
			Name: "banner", Aliases: []string{"logo"}, Category: catCore,
			Summary: "print the Mansa banner",
			Usage:   "banner",
			Run:     runBanner,
		},
		{
			Name: "completion", Category: catSystem,
			Summary: "print shell completion help",
			Usage:   "completion bash|zsh|fish|powershell",
			Run:     runCompletion,
		},
		{
			Name: "updates", Aliases: []string{"update"}, Category: catSystem,
			Summary: "check for updates",
			Usage:   "updates",
			Run:     runUpdates,
		},
		{
			Name: "quit", Aliases: []string{"exit", "q"}, Category: catCore,
			Summary: "leave the console",
			Usage:   "quit",
			Run:     func(_ *Console, _ *Parsed) error { return errExit },
		},
	}
}
