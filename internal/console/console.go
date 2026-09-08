// Package console implements Mansa's interactive wireless console: a
// persistent assessment session with a contextual prompt, command history,
// typed argument parsing, and tabular result rendering. It reuses the same
// application layer as the one-shot CLI — nothing about wireless assessment
// is duplicated here.
//
// Launching `mansa` with no subcommand enters this console; every existing
// one-shot command keeps working unchanged.
package console

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ergochat/readline"
	"golang.org/x/term"

	"github.com/QYVORA/qyvora-mansa/internal/app"
	"github.com/QYVORA/qyvora-mansa/internal/version"
)

// errExit is the internal sentinel returned by exit commands.
var errExit = errors.New("exit")

// Options configure a console instance.
type Options struct {
	In          io.Reader
	Out         io.Writer
	Err         io.Writer
	Interactive bool
	App         *app.AppState
}

// Console is one interactive Mansa session.
type Console struct {
	in          io.Reader
	out         io.Writer
	errW        io.Writer
	interactive bool
	app         *app.AppState

	cmds    map[string]*Command
	aliases map[string]string
	hist    *History
	lr      lineReader
	ui      *consoleUI

	iface      string
	sim        bool
	authorized bool
	current    *docSession

	cancelMu    sync.Mutex
	opCtx       context.Context
	opCancel    context.CancelFunc
	interrupted atomic.Bool
}

// docSession is the in-memory state for the last completed pipeline result
// plus a handle to persisted sessions.
type docSession struct {
	sessID  string
	summary string
}

// New builds a console from opts.
func New(opts Options) *Console {
	c := &Console{
		in:          opts.In,
		out:         opts.Out,
		errW:        opts.Err,
		interactive: opts.Interactive,
		app:         opts.App,
		hist:        NewHistory(),
	}
	if c.in == nil {
		c.in = os.Stdin
	}
	if c.out == nil {
		c.out = os.Stdout
	}
	if c.errW == nil {
		c.errW = os.Stderr
	}
	c.ui = newConsoleUI(c.out)
	c.registerCommands()
	return c
}

// Run drives the read-eval loop until exit/quit/Ctrl+D.
func (c *Console) Run(rootCtx context.Context) int {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			c.interrupted.Store(true)
			c.cancelOperation()
		}
	}()

	var lr lineReader = newPipeReader(c.in)
	if c.interactive && term.IsTerminal(int(os.Stdin.Fd())) {
		if instance, err := c.newReadline(); err == nil {
			lr = &readlineReader{rl: instance}
			defer instance.Close() //nolint:errcheck
		}
	}
	c.lr = lr

	if c.interactive {
		c.printBanner()
		c.hud()
		c.ui.Status("*", "console ready. type 'help' for commands.")
	}

	for {
		line, rerr := lr.Read(c.Prompt())
		switch {
		case errors.Is(rerr, io.EOF):
			if c.interactive {
				fmt.Fprintln(c.out)
			}
			return 0
		case errors.Is(rerr, readline.ErrInterrupt):
			fmt.Fprintln(c.out, "^C")
			continue
		case rerr != nil:
			return 0
		}

		if c.execute(rootCtx, line) {
			return 0
		}
		if c.interactive {
			c.hud()
		}
		c.interrupted.Store(false)
	}
}

// newReadline builds the TTY line editor with persistent history.
func (c *Console) newReadline() (*readline.Instance, error) {
	cfg := &readline.Config{
		Prompt:          "mansa > ",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistoryLimit:    historyLimit,
		AutoComplete:    c.newCompleter(),
	}
	if c.interactive {
		if path, ok := historyPath(); ok {
			cfg.HistoryFile = path
		}
	}
	return readline.NewEx(cfg)
}

// execute parses and dispatches one input line.
func (c *Console) execute(rootCtx context.Context, line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	c.hist.Add(trimmed)

	opCtx, cancel := context.WithCancel(rootCtx)
	defer cancel()
	c.setOpCancel(opCtx, cancel)

	toks, terr := tokenize(trimmed)
	if terr != nil {
		c.failf("%v", terr)
		return false
	}

	word := strings.ToLower(toks[0])
	name := word
	if resolved, ok := c.aliases[word]; ok {
		name = resolved
	}
	cmd, ok := c.cmds[name]
	if !ok {
		c.failf("Unknown command: %s", word)
		if hint := c.suggest(word); hint != "" {
			fmt.Fprintf(c.errW, "Did you mean '%s'?\n", hint)
		}
		fmt.Fprintln(c.errW, "Try 'help'.")
		return false
	}

	parsed, perr := parse(name, trimmed, toks[1:], cmd.flagSpecs())
	if perr != nil {
		c.failf("%v", perr)
		return false
	}

	if err := cmd.Run(c, parsed); err != nil {
		if errors.Is(err, errExit) {
			return true
		}
		c.failf("%v", err)
	}
	return false
}

// ---- output helpers ---------------------------------------------------

func (c *Console) printf(format string, a ...any) {
	fmt.Fprintf(c.out, format, a...)
}

func (c *Console) ok(format string, a ...any) {
	fmt.Fprintf(c.out, "[+] %s\n", fmt.Sprintf(format, a...))
}

func (c *Console) failf(format string, a ...any) {
	fmt.Fprintf(c.errW, "[!] %s\n", fmt.Sprintf(format, a...))
}

// OpContext returns the currently executing command's context.
func (c *Console) OpContext() context.Context {
	c.cancelMu.Lock()
	defer c.cancelMu.Unlock()
	if c.opCtx != nil {
		return c.opCtx
	}
	return context.Background()
}

func (c *Console) setOpCancel(ctx context.Context, cancel context.CancelFunc) {
	c.cancelMu.Lock()
	c.opCtx = ctx
	c.opCancel = cancel
	c.cancelMu.Unlock()
}

func (c *Console) cancelOperation() {
	c.cancelMu.Lock()
	if c.opCancel != nil {
		c.opCancel()
	}
	c.cancelMu.Unlock()
}

func (c *Console) hud() {
	if !c.interactive {
		return
	}
	iface := c.iface
	if iface == "" {
		iface = "none"
	}
	if c.app != nil && c.app.Backend != nil {
		mode := c.app.Backend.Name()
		if c.sim {
			mode = "simulation"
		}
		c.ui.HUD(iface, mode, "mansa", version.Version)
	}
}

func (c *Console) printBanner() {
	v := version.Version
	if v == "" {
		v = "dev"
	}
	c.ui.Banner("Wireless Security Assessment Framework")
	c.ui.BannerFoot(v)
}

// ---- line readers -----------------------------------------------------

type lineReader interface {
	Read(prompt string) (string, error)
	Close() error
}

type readlineReader struct{ rl *readline.Instance }

func (r *readlineReader) Read(prompt string) (string, error) {
	r.rl.SetPrompt(prompt)
	return r.rl.Readline()
}

func (r *readlineReader) Close() error { return r.rl.Close() }

type pipeReader struct{ scanner *bufio.Scanner }

func newPipeReader(in io.Reader) *pipeReader {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return &pipeReader{scanner: sc}
}

func (p *pipeReader) Read(_ string) (string, error) {
	if !p.scanner.Scan() {
		return "", io.EOF
	}
	return p.scanner.Text(), nil
}

func (p *pipeReader) Close() error { return nil }
