//go:build linux

package transport

import "testing"

func TestValidateMonitorName(t *testing.T) {
	for _, tc := range []struct {
		parent, name string
		wantErr      bool
	}{{"wlan0", "mansa-mon0", false}, {"", "mansa-mon0", true}, {"wlan0", "", true}, {"wlan0", "name/with/slash", true}, {"wlan0", "1234567890123456", true}} {
		err := validateMonitorName(tc.parent, tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateMonitorName(%q,%q) err=%v", tc.parent, tc.name, err)
		}
	}
}
