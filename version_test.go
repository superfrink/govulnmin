package main

import "testing"

func TestParseVersion(t *testing.T) {
	ok := map[string]string{
		"v1.2.3":                             "1.2.3",
		"1.2.3":                              "1.2.3",
		"go1.25.0":                           "1.25.0",
		"1.22":                               "1.22.0",
		"v0.3.0":                             "0.3.0",
		"0":                                  "0.0.0",
		"v2.0.0+incompatible":                "2.0.0",
		"v0.0.0-20200101120000-abcdef123456": "0.0.0-20200101120000-abcdef123456",
		"1.27.0-0":                           "1.27.0-0",
	}
	for in, want := range ok {
		v, got := parseVersion(in)
		if !got {
			t.Errorf("parseVersion(%q) failed", in)
			continue
		}
		if v.String() != want {
			t.Errorf("parseVersion(%q) = %q, want %q", in, v.String(), want)
		}
	}
	for _, bad := range []string{"", "v", "x.y.z", "1.2.3.4", "go", "-1.2.3"} {
		if _, got := parseVersion(bad); got {
			t.Errorf("parseVersion(%q) succeeded, want failure", bad)
		}
	}
}

func TestCompareVersion(t *testing.T) {
	order := []string{
		"0",
		"v0.3.0",
		"v0.3.7",
		"v0.3.8",
		"v0.10.0",
		"v0.39.0",
		"v1.0.0-alpha",
		"v1.0.0-alpha.1",
		"v1.0.0-beta",
		"v1.0.0-rc.1",
		"v1.0.0",
		"v1.0.1",
		"v1.2.3",
		"v1.10.0",
		"go1.25.0",
		"go1.26.11",
		"v2.0.0",
	}
	for i := 1; i < len(order); i++ {
		a, _ := parseVersion(order[i-1])
		b, _ := parseVersion(order[i])
		if c := compareVersion(a, b); c >= 0 {
			t.Errorf("compareVersion(%s, %s) = %d, want < 0", order[i-1], order[i], c)
		}
		if c := compareVersion(b, a); c <= 0 {
			t.Errorf("compareVersion(%s, %s) = %d, want > 0", order[i], order[i-1], c)
		}
		if c := compareVersion(a, a); c != 0 {
			t.Errorf("compareVersion(%s, %s) = %d, want 0", order[i-1], order[i-1], c)
		}
	}
}

func TestModuleMajor(t *testing.T) {
	cases := map[string]int{
		"golang.org/x/text":           0,
		"github.com/foo/bar/v2":       2,
		"github.com/foo/bar/v10":      10,
		"github.com/foo/v2ish":        0,
		"gopkg.in/yaml.v3":            3,
		"gopkg.in/yaml.v2":            2,
		"github.com/foo/bar":          0,
		"github.com/foo/v2/submodule": 0,
	}
	for in, want := range cases {
		if got := moduleMajor(in); got != want {
			t.Errorf("moduleMajor(%q) = %d, want %d", in, got, want)
		}
	}
}
