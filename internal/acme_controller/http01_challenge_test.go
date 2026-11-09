package acme_controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestKeyAuthorizationMatches(t *testing.T) {
	thumb := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03}
	const thumbB64 = "3q2-7wECAw"
	const token = "abc_DEF-123"
	good := token + "." + thumbB64

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"exact", good, true},
		{"trailing newline", good + "\n", true},
		{"trailing CRLF", good + "\r\n", true},
		{"trailing spaces", good + "  ", true},
		{"trailing tab", good + "\t", true},
		{"mixed trailing whitespace", good + " \t\r\n", true},

		{"empty", "", false},
		{"no dot", token + thumbB64, false},
		{"wrong token", "other." + thumbB64, false},
		{"wrong thumbprint", token + ".3q2-7wECBA", false},
		{"missing thumbprint", token + ".", false},
		{"missing token", "." + thumbB64, false},
		{"thumbprint not base64url", token + ".!!!", false},
		{"padded thumbprint", good + "=", false},
		{"leading whitespace", " " + good, false},
		{"extra content after", good + " extra", false},
		{"extra dot segment", good + ".more", false},
		{"upper case token", strings.ToUpper(token) + "." + thumbB64, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyAuthorizationMatches(tt.body, token, thumb); got != tt.want {
				t.Errorf("keyAuthorizationMatches(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestFetchKeyAuthorization(t *testing.T) {
	serve := func(handler http.HandlerFunc) *httptest.Server {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return srv
	}
	client := &http.Client{Timeout: 2 * time.Second}

	t.Run("ok", func(t *testing.T) {
		srv := serve(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("token.thumb")) })
		got, err := fetchKeyAuthorization(client, srv.URL)
		if err != nil || got != "token.thumb" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("non-200 responses are failures even with a matching body", func(t *testing.T) {
		for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusForbidden, http.StatusNoContent} {
			srv := serve(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte("token.thumb"))
			})
			if got, err := fetchKeyAuthorization(client, srv.URL); err == nil {
				t.Errorf("status %d: expected an error, got %q", status, got)
			}
		}
	})

	t.Run("redirects are followed", func(t *testing.T) {
		target := serve(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("token.thumb")) })
		srv := serve(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) })
		if got, err := fetchKeyAuthorization(client, srv.URL); err != nil || got != "token.thumb" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("oversized body is rejected", func(t *testing.T) {
		srv := serve(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(strings.Repeat("a", maxKeyAuthorizationSize+1)))
		})
		if got, err := fetchKeyAuthorization(client, srv.URL); err == nil {
			t.Fatalf("expected an error, got %d bytes", len(got))
		}
	})

	t.Run("body at the limit is accepted", func(t *testing.T) {
		srv := serve(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(strings.Repeat("a", maxKeyAuthorizationSize)))
		})
		if _, err := fetchKeyAuthorization(client, srv.URL); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("endless body doesn't hang or exhaust memory", func(t *testing.T) {
		srv := serve(func(w http.ResponseWriter, r *http.Request) {
			// Never ends on its own: only the client giving up stops it
			chunk := []byte(strings.Repeat("a", 4096))
			for {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		})
		start := time.Now()
		if _, err := fetchKeyAuthorization(client, srv.URL); err == nil {
			t.Fatal("expected an error")
		}
		if time.Since(start) > time.Second {
			t.Errorf("took %v: the body should be cut off at the limit", time.Since(start))
		}
	})

	t.Run("slow server times out", func(t *testing.T) {
		release := make(chan struct{})
		srv := serve(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		defer close(release)

		fast := &http.Client{Timeout: 100 * time.Millisecond}
		start := time.Now()
		if _, err := fetchKeyAuthorization(fast, srv.URL); err == nil {
			t.Fatal("expected a timeout")
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("took %v", time.Since(start))
		}
	})

	t.Run("connection failure", func(t *testing.T) {
		srv := serve(func(w http.ResponseWriter, r *http.Request) {})
		url := srv.URL
		srv.Close()
		if _, err := fetchKeyAuthorization(client, url); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("the production client has a timeout", func(t *testing.T) {
		if http01Client.Timeout <= 0 {
			t.Error("a hung validation target would hold the authz lock forever")
		}
	})
}
