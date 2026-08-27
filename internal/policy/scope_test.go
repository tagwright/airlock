// SPDX-License-Identifier: GPL-3.0-or-later

package policy

import "testing"

func TestParseScope(t *testing.T) {
	cases := []struct {
		in      string
		want    Scope
		wantErr bool
	}{
		{"external", External, false},
		{"all", All, false},
		{"", 0, true},
		{"External", 0, true}, // no case folding
		{"internal", 0, true},
	}
	for _, c := range cases {
		got, err := ParseScope(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseScope(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseScope(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseScope(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestScopeString(t *testing.T) {
	cases := []struct {
		s    Scope
		want string
	}{
		{External, "external"},
		{All, "all"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Scope(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}
