package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-mansa/internal/app"
	"github.com/QYVORA/qyvora-mansa/internal/session"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func TestRequiresAssessment(t *testing.T) {
	tests := []struct {
		name string
		ap   models.AccessPoint
		want bool
	}{
		{"open network", models.AccessPoint{SSID: "open", Security: models.SecurityAdvertisement{Auth: "open"}}, true},
		{"no auth advertised", models.AccessPoint{SSID: "x", Security: models.SecurityAdvertisement{Auth: ""}}, true},
		{"security disabled", models.AccessPoint{SSID: "x", Security: models.SecurityAdvertisement{Enabled: false}}, true},
		{"disabled with empty ssid", models.AccessPoint{}, false},
		{"wep", models.AccessPoint{SSID: "x", Security: models.SecurityAdvertisement{Enabled: true, Auth: "WEP"}}, true},
		{"wpa3", models.AccessPoint{SSID: "x", Security: models.SecurityAdvertisement{Enabled: true, Auth: "WPA3-SAE"}}, false},
	}
	for _, tt := range tests {
		if got := requiresAssessment(tt.ap); got != tt.want {
			t.Errorf("%s: requiresAssessment = %v want %v", tt.name, got, tt.want)
		}
	}
}

func testConsole(t *testing.T) (*Console, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	appState := &app.AppState{
		Cfg:   viper.New(),
		Store: session.NewStore(t.TempDir()),
	}
	out := &bytes.Buffer{}
	errW := &bytes.Buffer{}
	return New(Options{Out: out, Err: errW, App: appState}), out, errW
}

func TestRunAuthorizeDeclinedWithoutConfirmation(t *testing.T) {
	c, _, errW := testConsole(t)
	p, err := parse("authorize", "authorize", nil, (&Command{Flags: []FlagSpec{{Name: "yes", Kind: FlagBool}}}).flagSpecs())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := runAuthorize(c, p); err != nil {
		t.Fatalf("runAuthorize: %v", err)
	}
	if c.authorized {
		t.Error("authorize without --yes in a non-interactive session must not grant access")
	}
	if !strings.Contains(errW.String(), "declined") {
		t.Errorf("expected a decline notice, got: %s", errW.String())
	}
}

func TestRunAuthorizeWithYes(t *testing.T) {
	c, _, _ := testConsole(t)
	p, err := parse("authorize", "authorize --yes", []string{"--yes"}, (&Command{Flags: []FlagSpec{{Name: "yes", Kind: FlagBool}}}).flagSpecs())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := runAuthorize(c, p); err != nil {
		t.Fatalf("runAuthorize: %v", err)
	}
	if !c.authorized {
		t.Error("authorize --yes should grant live scope")
	}
}

func TestRunEnvironmentBoundedRows(t *testing.T) {
	c, out, _ := testConsole(t)
	sess := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0", Interface: "wlan0"})
	for i := 0; i < maxEnvironmentRows+5; i++ {
		sess.AccessPoints = append(sess.AccessPoints, models.AccessPoint{
			BSSID:    models.NewID("b"),
			SSID:     "open",
			Channel:  6,
			Band:     "2.4GHz",
			Security: models.SecurityAdvertisement{Auth: "open", Enabled: true},
		})
	}
	if _, err := c.app.Store.Save(sess); err != nil {
		t.Fatalf("save: %v", err)
	}
	c.current = &docSession{sessID: sess.ID}
	p, err := parse("environment", "environment", nil, (&Command{}).flagSpecs())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := runEnvironment(c, p); err != nil {
		t.Fatalf("runEnvironment: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "networks requiring assessment") {
		t.Errorf("expected summary output, got: %s", got)
	}
	// Exactly the bounded number of AP rows (each row carries "open" in both the
	// ssid and security columns), plus the overflow note.
	if n := strings.Count(got, "open"); n != 2*maxEnvironmentRows {
		t.Errorf("expected exactly %d bounded rows mentioning %q, got %d", maxEnvironmentRows, "open", n)
	}
	if !strings.Contains(got, "and 5 more") {
		t.Errorf("expected overflow note mentioning 5 more, got: %s", got)
	}
}
