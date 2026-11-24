package main

import (
	"fmt"
	"strconv"
	"strings"
)

// version is a Go module or toolchain version, e.g. v1.2.3, 1.2.3-pre,
// v2.0.0+incompatible, or go1.25.0.
type version struct {
	major, minor, patch int
	pre                 string // "" means a release
}

func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "go")
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return version{}, false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 { // build metadata, ignored
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return version{}, false
	}
	var nums [3]int
	for i, p := range parts {
		if p == "" {
			return version{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return version{}, false
		}
		nums[i] = n
	}
	return version{nums[0], nums[1], nums[2], pre}, true
}

// compareVersion returns -1, 0 or 1 as a<b, a==b, a>b.
func compareVersion(a, b version) int {
	if c := compareInt(a.major, b.major); c != 0 {
		return c
	}
	if c := compareInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := compareInt(a.patch, b.patch); c != 0 {
		return c
	}
	return comparePre(a.pre, b.pre)
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func comparePre(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" { // a release outranks any pre-release
		return 1
	}
	if b == "" {
		return -1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aNum := strconv.Atoi(as[i])
		bn, bNum := strconv.Atoi(bs[i])
		switch {
		case aNum == nil && bNum == nil:
			if c := compareInt(an, bn); c != 0 {
				return c
			}
		case aNum == nil: // numeric identifiers sort before alphanumeric
			return -1
		case bNum == nil:
			return 1
		case as[i] != bs[i]:
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	return compareInt(len(as), len(bs))
}

// moduleMajor returns the major version encoded in a module path: 0 for
// un-suffixed paths (which cover v0 and v1), N for a /vN suffix or gopkg.in's
// .vN form.
func moduleMajor(path string) int {
	if strings.HasPrefix(path, "gopkg.in/") {
		if i := strings.LastIndex(path, ".v"); i >= 0 {
			if n, err := strconv.Atoi(path[i+2:]); err == nil && n >= 2 {
				return n
			}
		}
		return 0
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		if s := path[i+1:]; len(s) > 1 && s[0] == 'v' {
			if n, err := strconv.Atoi(s[1:]); err == nil && n >= 2 {
				return n
			}
		}
	}
	return 0
}

func (v version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
	if v.pre != "" {
		s += "-" + v.pre
	}
	return s
}
