package selfupdate

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.10.0", "1.2.0", 1},
		{"1.2.0", "1.10.0", -1},
		{"1.0.0", "1.0", 1},
		{"1.0", "1.0.0", -1},
		{"v1.2.3", "1.2.3", 0},
		{"2.0.0-rc.1", "2.0.0", -1},
		{"2.0.0", "2.0.0-rc.1", 1},
		{"2.0.0+meta", "2.0.0", 0},
		{"0.9.9", "1.0.0", -1},
	}
	for _, tt := range tests {
		got := CompareVersions(tt.a, tt.b)
		switch {
		case tt.want > 0 && got <= 0:
			t.Errorf("CompareVersions(%q,%q)=%d want >0", tt.a, tt.b, got)
		case tt.want < 0 && got >= 0:
			t.Errorf("CompareVersions(%q,%q)=%d want <0", tt.a, tt.b, got)
		case tt.want == 0 && got != 0:
			t.Errorf("CompareVersions(%q,%q)=%d want 0", tt.a, tt.b, got)
		}
	}
}

func TestParseVersionOrdered(t *testing.T) {
	nums := parseVersion("1.10.2")
	if len(nums) != 3 || nums[0] != 1 || nums[1] != 10 || nums[2] != 2 {
		t.Errorf("parseVersion(1.10.2)=%v want [1 10 2]", nums)
	}
}
