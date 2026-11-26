package warpsignature

import (
	"regexp"
	"slices"
	"testing"
)

var tagRe = regexp.MustCompile(`<(\w+)(?:\s+([^>]*))?>`)

// Токены только из пересечения kernel-модуля и amneziawg-go.
func assertAllowedTokens(t *testing.T, pattern string) {
	t.Helper()
	rest := tagRe.ReplaceAllString(pattern, "")
	if rest != "" {
		t.Fatalf("stray text outside tokens: %q", rest)
	}
	for _, m := range tagRe.FindAllStringSubmatch(pattern, -1) {
		switch m[1] {
		case "b":
			if !regexp.MustCompile(`^0x([0-9a-f]{2})+$`).MatchString(m[2]) {
				t.Fatalf("bad <b> payload %q", m[2])
			}
		case "t":
			if m[2] != "" {
				t.Fatalf("<t> takes no argument: %q", m[0])
			}
		case "r", "rc", "rd":
			if !regexp.MustCompile(`^[1-9]\d{0,3}$`).MatchString(m[2]) {
				t.Fatalf("bad %s size %q", m[1], m[2])
			}
		default:
			t.Fatalf("forbidden token %q", m[0])
		}
	}
}

func hostPoolHas(h string) bool { return slices.Contains(hostPool, h) }
