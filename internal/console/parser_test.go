package console

import "testing"

func testSpec() map[string]FlagSpec {
	return map[string]FlagSpec{
		"sim":       {Name: "sim", Kind: FlagBool},
		"format":    {Name: "format", Kind: FlagString},
		"out":       {Name: "out", Kind: FlagString},
		"timeout":   {Name: "timeout", Kind: FlagInt},
		"target":    {Name: "target", Kind: FlagStringSlice},
		"interact":  {Name: "interact", Kind: FlagBool},
		"authorize": {Name: "authorize", Kind: FlagString},
	}
}

func TestParseFlagsEqualForm(t *testing.T) {
	p, err := parse("assess", "assess --sim --format=json --timeout=15", []string{"assess", "--sim", "--format=json", "--timeout=15"}, testSpec())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Bool("sim") {
		t.Error("expected --sim true")
	}
	if got := p.Str("format"); got != "json" {
		t.Errorf("format=%q want json", got)
	}
	if got := p.Int("timeout", 0); got != 15 {
		t.Errorf("timeout=%d want 15", got)
	}
}

func TestParseFlagsSpaceSeparated(t *testing.T) {
	p, err := parse("report", "report --format json --out /tmp/report.json", []string{"report", "--format", "json", "--out", "/tmp/report.json"}, testSpec())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := p.Str("format"); got != "json" {
		t.Errorf("format=%q want json", got)
	}
	if got := p.Str("out"); got != "/tmp/report.json" {
		t.Errorf("out=%q want /tmp/report.json", got)
	}
}

func TestParseFlagValueConsumedKeepsPositionals(t *testing.T) {
	p, err := parse("use", "use wlan0", []string{"wlan0"}, testSpec())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Arg(0) != "wlan0" || p.ArgsLen() != 1 {
		t.Errorf("args=%v want [wlan0]", p.Args)
	}
}

func TestParseUnknownFlag(t *testing.T) {
	_, err := parse("scan", "scan --bogus", []string{"scan", "--bogus"}, testSpec())
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseStringSlice(t *testing.T) {
	p, err := parse("scan", "scan --target a --target b", []string{"scan", "--target", "a", "--target", "b"}, testSpec())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := p.Strs("target"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("target=%v want [a b]", got)
	}
}

func TestParseBoolExplicit(t *testing.T) {
	p, err := parse("scan", "scan --sim=false", []string{"scan", "--sim=false"}, testSpec())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Bool("sim") {
		t.Error("expected --sim=false")
	}
}

func TestParseMissingValue(t *testing.T) {
	if _, err := parse("report", "report --format", []string{"report", "--format"}, testSpec()); err == nil {
		t.Fatal("expected error for missing value")
	}
}

func TestParseIntRejectsNonInt(t *testing.T) {
	if _, err := parse("scan", "scan --timeout abc", []string{"scan", "--timeout", "abc"}, testSpec()); err == nil {
		t.Fatal("expected error for int flag with non-int value")
	}
}

func TestTokenizeQuoted(t *testing.T) {
	got, err := tokenize(`report --title "hello world" 'a b'`)
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	want := []string{"report", "--title", "hello world", "a b"}
	if len(got) != len(want) {
		t.Fatalf("tokens=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestTokenizeUnterminatedQuote(t *testing.T) {
	if _, err := tokenize(`report "oops`); err == nil {
		t.Fatal("expected error on unterminated quote")
	}
}

func TestFlagValueDefaults(t *testing.T) {
	p, err := parse("scan", "scan", []string{"scan"}, testSpec())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Str("format") != "" {
		t.Error("default format should be empty")
	}
	if p.Int("timeout", 30) != 30 {
		t.Error("default timeout should be 30")
	}
	if p.Bool("sim") {
		t.Error("default sim should be false")
	}
}
