package links

import (
	"testing"
)

func TestPath(t *testing.T) {
	l := LinkController{BaseURL: "https://example.com/acme"}

	for _, in := range []string{"foo", "/foo"} {
		p := l.Path(in)
		if p.Relative() != "/foo" {
			t.Errorf("Path(%q).Relative() = %q, want /foo", in, p.Relative())
		}
		if p.Abs() != "https://example.com/acme/foo" {
			t.Errorf("Path(%q).Abs() = %q", in, p.Abs())
		}
	}
}

func TestCompareURL(t *testing.T) {
	l := LinkController{BaseURL: "https://example.com/acme"}

	if !l.CompareURL("/acme/new-account", "https://example.com/acme/new-account") {
		t.Error("expected matching URL to compare equal")
	}
	if l.CompareURL("/acme/new-account", "https://example.com/acme/new-order") {
		t.Error("expected different URL to compare unequal")
	}
	if l.CompareURL("/acme/new-account", "https://evil.example.com/acme/new-account") {
		t.Error("expected different host to compare unequal")
	}
}
