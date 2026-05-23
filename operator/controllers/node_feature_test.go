package controllers

import "testing"

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		input         string
		major, minor  int
		expectErr     bool
	}{
		{"6.9.0-generic", 6, 9, false},
		{"6.12.3-1-default", 6, 12, false},
		{"5.15.0-1064-azure", 5, 15, false},
		{"6.17.0-23-generic", 6, 17, false},
		{"4.18.0-372.el8.x86_64", 4, 18, false},
		{"badversion", 0, 0, true},
	}

	for _, tt := range tests {
		major, minor, err := parseKernelVersion(tt.input)
		if tt.expectErr {
			if err == nil {
				t.Errorf("parseKernelVersion(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKernelVersion(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if major != tt.major || minor != tt.minor {
			t.Errorf("parseKernelVersion(%q) = %d.%d, want %d.%d",
				tt.input, major, minor, tt.major, tt.minor)
		}
	}
}

func TestArenaCapableThreshold(t *testing.T) {
	tests := []struct {
		major, minor int
		want         bool
	}{
		{6, 9, true},
		{6, 10, true},
		{6, 17, true},
		{7, 0, true},
		{6, 8, false},
		{5, 15, false},
		{4, 18, false},
	}

	for _, tt := range tests {
		got := tt.major > 6 || (tt.major == 6 && tt.minor >= 9)
		if got != tt.want {
			t.Errorf("arenaCapable(%d.%d) = %v, want %v",
				tt.major, tt.minor, got, tt.want)
		}
	}
}
