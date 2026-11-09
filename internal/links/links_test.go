package links

import (
	"encoding/json"
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

// RFC 8555 7.1.1: newAuthz must be omitted when pre-authorization isn't supported, and
// unset meta fields shouldn't be advertised as empty values
func TestGenerateDirectory(t *testing.T) {
	directory := func(l LinkController) map[string]any {
		raw, err := json.Marshal(l.GenerateDirectory())
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("bare", func(t *testing.T) {
		d := directory(LinkController{BaseURL: "https://example.com/acme"})

		if _, ok := d["newAuthz"]; ok {
			t.Error("newAuthz must be omitted")
		}
		for _, k := range []string{"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"} {
			if v, _ := d[k].(string); v == "" {
				t.Errorf("%s missing", k)
			}
		}
		meta, _ := d["meta"].(map[string]any)
		for _, k := range []string{"termsOfService", "website", "caaIdentities"} {
			if v, ok := meta[k]; ok {
				t.Errorf("unset meta field %s should be omitted, got %v", k, v)
			}
		}
	})

	t.Run("configured meta", func(t *testing.T) {
		d := directory(LinkController{
			BaseURL:     "https://example.com/acme",
			MetaTosURL:  "https://example.com/tos",
			MetaWebsite: "https://example.com",
			MetaCAAs:    []string{"example.com"},
		})

		meta := d["meta"].(map[string]any)
		if meta["termsOfService"] != "https://example.com/tos" || meta["website"] != "https://example.com" {
			t.Errorf("meta = %v", meta)
		}
		if caas, _ := meta["caaIdentities"].([]any); len(caas) != 1 || caas[0] != "example.com" {
			t.Errorf("caaIdentities = %v", meta["caaIdentities"])
		}
	})
}
