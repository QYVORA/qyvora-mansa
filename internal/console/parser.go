package console

import (
	"fmt"
	"strings"
)

// FlagKind is the type of a console flag.
type FlagKind int

const (
	FlagBool FlagKind = iota
	FlagString
	FlagInt
	FlagStringSlice
)

// FlagSpec declares one console flag.
type FlagSpec struct {
	Name string
	Kind FlagKind
}

// ParseError is a concise, user-facing parsing failure.
type ParseError struct{ msg string }

func (e *ParseError) Error() string { return e.msg }

func parseErrf(format string, a ...any) error {
	return &ParseError{msg: fmt.Sprintf(format, a...)}
}

// Parsed holds the result of parsing a command line.
type Parsed struct {
	Name  string
	Raw   string
	Args  []string
	Flags map[string]flagValue
	spec  map[string]FlagSpec
}

type flagValue struct {
	s     string
	i     int
	b     bool
	strs  []string
	isSet bool
}

// Bool returns the boolean value of flag name.
func (p *Parsed) Bool(name string) bool {
	if p == nil {
		return false
	}
	if f, ok := p.Flags[name]; ok && f.b {
		return true
	}
	return false
}

// Str returns the string value of flag name.
func (p *Parsed) Str(name string) string {
	if p == nil {
		return ""
	}
	if f, ok := p.Flags[name]; ok && f.isSet {
		return f.s
	}
	return ""
}

// Strs returns the repeated string values of flag name.
func (p *Parsed) Strs(name string) []string {
	if p == nil {
		return nil
	}
	if f, ok := p.Flags[name]; ok {
		return f.strs
	}
	return nil
}

// Int returns the integer value of flag name or def when absent.
func (p *Parsed) Int(name string, def int) int {
	if p == nil {
		return def
	}
	if f, ok := p.Flags[name]; ok && f.isSet {
		return f.i
	}
	return def
}

// Arg returns the i-th positional argument.
func (p *Parsed) Arg(i int) string {
	if p == nil || i < 0 || i >= len(p.Args) {
		return ""
	}
	return p.Args[i]
}

// ArgsLen returns the positional argument count.
func (p *Parsed) ArgsLen() int {
	if p == nil {
		return 0
	}
	return len(p.Args)
}

// tokenize splits a line honoring quoted strings and escapes.
func tokenize(line string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	i := 0
	inTok := false
	for i < len(line) {
		ch := line[i]
		switch ch {
		case ' ':
			if inTok {
				toks = append(toks, cur.String())
				cur.Reset()
				inTok = false
			}
			i++
		case '\'':
			if inTok {
				return nil, parseErrf("invalid quote inside token")
			}
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, parseErrf("unterminated single quote")
			}
			cur.WriteString(line[i+1 : i+1+j])
			inTok = true
			i += j + 2
		case '"':
			inTok = true
			res, next, err := scanDoubleQuoted(line, i+1)
			if err != nil {
				return nil, err
			}
			cur.WriteString(res)
			i = next
		case '\\':
			if i+1 >= len(line) {
				return nil, parseErrf("trailing backslash")
			}
			cur.WriteByte(line[i+1])
			inTok = true
			i += 2
		default:
			cur.WriteByte(ch)
			inTok = true
			i++
		}
	}
	if inTok {
		toks = append(toks, cur.String())
	}
	return toks, nil
}

func scanDoubleQuoted(line string, from int) (string, int, error) {
	var b strings.Builder
	i := from
	for i < len(line) {
		switch line[i] {
		case '\\':
			if i+1 >= len(line) {
				return "", 0, parseErrf("trailing backslash")
			}
			if line[i+1] == '"' || line[i+1] == '\\' {
				b.WriteByte(line[i+1])
				i += 2
				continue
			}
			b.WriteByte(line[i])
			i++
		case '"':
			return b.String(), i + 1, nil
		default:
			b.WriteByte(line[i])
			i++
		}
	}
	return "", 0, parseErrf("unterminated double quote")
}

// parse parses tokens into a Parsed value.
func parse(name, raw string, toks []string, spec map[string]FlagSpec) (*Parsed, error) {
	p := &Parsed{Name: name, Raw: raw, Flags: map[string]flagValue{}, spec: spec}
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		if isFlagToken(tok) {
			fl, val, hasVal := splitFlag(tok)
			f, ok := spec[fl]
			if !ok {
				return nil, parseErrf("unknown flag --%s", fl)
			}
			if (f.Kind == FlagString || f.Kind == FlagInt || f.Kind == FlagStringSlice) && !hasVal {
				// Space-separated value: consume the following token.
				if i+1 >= len(toks) {
					return nil, parseErrf("--%s requires a value", fl)
				}
				val = toks[i+1]
				hasVal = true
				i++
			}
			switch f.Kind {
			case FlagBool:
				if hasVal {
					switch strings.ToLower(val) {
					case "true", "1":
						p.Flags[fl] = flagValue{b: true}
					case "false", "0":
						p.Flags[fl] = flagValue{b: false}
					default:
						return nil, parseErrf("invalid value for --%s: %q (true, false)", fl, val)
					}
				} else {
					p.Flags[fl] = flagValue{b: true, isSet: true}
				}
			case FlagString, FlagInt:
				if !hasVal {
					return nil, parseErrf("--%s requires a value", fl)
				}
				if f.Kind == FlagInt {
					n := 0
					if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
						return nil, parseErrf("--%s expects an integer, got %q", fl, val)
					}
					p.Flags[fl] = flagValue{i: n, isSet: true}
				} else {
					p.Flags[fl] = flagValue{s: val, isSet: true}
				}
			case FlagStringSlice:
				if !hasVal {
					return nil, parseErrf("--%s requires a value", fl)
				}
				fv := p.Flags[fl]
				fv.strs = append(fv.strs, val)
				fv.isSet = true
				p.Flags[fl] = fv
			}
			continue
		}
		p.Args = append(p.Args, tok)
	}
	return p, nil
}

func splitFlag(tok string) (name, val string, hasVal bool) {
	tok = strings.TrimPrefix(tok, "--")
	tok = strings.TrimPrefix(tok, "-b")
	if idx := strings.IndexByte(tok, '='); idx >= 0 {
		return tok[:idx], tok[idx+1:], true
	}
	return tok, "", false
}

func isFlagToken(tok string) bool {
	if len(tok) < 2 || tok[0] != '-' {
		return false
	}
	if tok[1] == '-' {
		return true
	}
	return !isDigit(tok[1])
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
