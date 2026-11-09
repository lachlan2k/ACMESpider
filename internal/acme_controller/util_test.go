package acme_controller

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateIDAndToken(t *testing.T) {
	charset := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	tests := []struct {
		name     string
		gen      func() (string, error)
		wantSize int
	}{
		{"id", GenerateID, 16},
		{"challenge token", GenerateChallengeToken, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := map[string]bool{}
			for i := 0; i < 1000; i++ {
				v, err := tt.gen()
				if err != nil {
					t.Fatal(err)
				}
				if !charset.MatchString(v) {
					t.Fatalf("%q is not base64url without padding", v)
				}
				raw, err := base64.RawURLEncoding.DecodeString(v)
				if err != nil || len(raw) != tt.wantSize {
					t.Fatalf("%q decodes to %d bytes (err %v), want %d", v, len(raw), err, tt.wantSize)
				}
				if seen[v] {
					t.Fatalf("duplicate value %q", v)
				}
				seen[v] = true
			}
		})
	}
}

func TestInternalErrorProblem(t *testing.T) {
	cause := errors.New("boom")
	p := InternalErrorProblem(cause)

	if p.Type != serverInternalErr || p.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("unexpected problem: %+v", p)
	}
	if !errors.Is(p, cause) {
		t.Error("expected problem to unwrap to cause")
	}
	if p.ID() == "" || !strings.Contains(p.Detail, p.ID()) {
		t.Errorf("detail %q should reference ID %q", p.Detail, p.ID())
	}
	if strings.Contains(p.Detail, "boom") {
		t.Error("detail must not leak the wrapped error")
	}
	if InternalErrorProblem(cause).ID() == p.ID() {
		t.Error("IDs should be unique per problem")
	}
}
