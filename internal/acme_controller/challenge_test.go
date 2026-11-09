package acme_controller

import (
	"crypto"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

func TestSplitChallengeID(t *testing.T) {
	ac := newTestCtrl(t)

	tests := []struct {
		id        string
		wantAuthz string
		wantIndex int
		wantErr   bool
	}{
		{"abc00", "abc", 0, false},
		{"abc01", "abc", 1, false},
		{"abc0a", "abc", 10, false},
		{"abc0A", "abc", 10, false},
		{"abcff", "abc", 255, false},
		{"x00", "x", 0, false},

		{"", "", 0, true},
		{"00", "", 0, true},
		{"ab", "", 0, true},
		{"abczz", "", 0, true},
		{"abc0g", "", 0, true},
		{"abc 1", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			authz, idx, err := ac.splitChallengeID([]byte(tt.id))
			if tt.wantErr {
				expectProblem(t, err, malformedErr, http.StatusBadRequest)
				return
			}
			if err != nil || string(authz) != tt.wantAuthz || idx != tt.wantIndex {
				t.Fatalf("got (%q, %d, %v), want (%q, %d)", authz, idx, err, tt.wantAuthz, tt.wantIndex)
			}
		})
	}
}

// A signed index such as "-1" must be rejected: it used to parse as a negative index, pass the upper
// bounds check in InitiateChallenge, and panic in the HTTP-01 verify goroutine, crashing the process.
func TestSplitChallengeIDRejectsSignedIndex(t *testing.T) {
	ac := newTestCtrl(t)

	for _, id := range []string{"abc-1", "abc+1", "abc-0", "abc+0", "abc-f", "abc+f"} {
		t.Run(id, func(t *testing.T) {
			_, idx, err := ac.splitChallengeID([]byte(id))
			if err == nil {
				t.Fatalf("challenge ID %q was accepted with index %d", id, idx)
			}
			expectProblem(t, err, malformedErr, http.StatusBadRequest)
		})
	}
}

func TestMakeChallengeIDRoundTrips(t *testing.T) {
	ac := newTestCtrl(t)

	for _, idx := range []int{0, 1, 15, 16, 255} {
		id := ac.makeChallengeID("authz", idx)
		authz, got, err := ac.splitChallengeID([]byte(id))
		if err != nil || string(authz) != "authz" || got != idx {
			t.Errorf("index %d: id %q -> (%q, %d, %v)", idx, id, authz, got, err)
		}
	}
}

func TestInitiateChallengeRejections(t *testing.T) {
	ac := newTestCtrl(t)
	owner := ac.newTestAccount(t)
	other := ac.newTestAccount(t)
	order := ac.newTestOrder(t, owner, "a.example.com")
	authzID := order.AuthzIDs[0]

	t.Run("malformed id", func(t *testing.T) {
		_, err := ac.InitiateChallenge([]byte("x"), owner)
		expectProblem(t, err, malformedErr, http.StatusBadRequest)
	})
	t.Run("unknown authz", func(t *testing.T) {
		_, err := ac.InitiateChallenge([]byte("missing00"), owner)
		expectUnauthorized(t, err)
	})
	t.Run("other account", func(t *testing.T) {
		_, err := ac.InitiateChallenge([]byte(authzID+"00"), other)
		expectUnauthorized(t, err)
	})
	t.Run("signed challenge index", func(t *testing.T) {
		// Negative indexes used to reach the verify goroutine and panic, taking down the process
		for _, suffix := range []string{"-1", "+1", "-0", "-f"} {
			_, err := ac.InitiateChallenge([]byte(authzID+suffix), owner)
			expectProblem(t, err, malformedErr, http.StatusBadRequest)
		}
		authz, _ := ac.db.GetAuthz([]byte(authzID))
		if authz.Locked || authz.Challenges[0].Status != dtos.ChallengeStatusPending {
			t.Errorf("rejected request touched the authz: %+v", authz)
		}
	})
	t.Run("challenge index out of range", func(t *testing.T) {
		_, err := ac.InitiateChallenge([]byte(authzID+"01"), owner)
		expectProblem(t, err, malformedErr, http.StatusNotFound)
	})

	t.Run("authz already locked", func(t *testing.T) {
		ok, err := ac.db.TryTakeAuthzLock([]byte(authzID))
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		defer ac.db.UnlockAuthz([]byte(authzID))

		if _, err := ac.InitiateChallenge([]byte(authzID+"00"), owner); err == nil {
			t.Fatal("expected error for a challenge that is already in progress")
		}
		// Must not have clobbered the in-progress challenge
		authz, _ := ac.db.GetAuthz([]byte(authzID))
		if authz.Challenges[0].Status != dtos.ChallengeStatusPending {
			t.Errorf("challenge status = %s", authz.Challenges[0].Status)
		}
	})

	t.Run("challenge not pending", func(t *testing.T) {
		for _, status := range []string{dtos.ChallengeStatusProcessing, dtos.ChallengeStatusValid, dtos.ChallengeStatusInvalid} {
			ac.db.UpdateAuthz([]byte(authzID), func(a *db.DBAuthz) error { a.Challenges[0].Status = status; return nil })
			if _, err := ac.InitiateChallenge([]byte(authzID+"00"), owner); err == nil {
				t.Errorf("expected error for %s challenge", status)
			}
		}
	})

	t.Run("lock released after failure", func(t *testing.T) {
		ok, err := ac.db.TryTakeAuthzLock([]byte(authzID))
		if err != nil || !ok {
			t.Fatalf("authz lock leaked after failed challenge: ok=%v err=%v", ok, err)
		}
		ac.db.UnlockAuthz([]byte(authzID))
	})
}

func TestInitiateChallengeSuccess(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)
	order := ac.newTestOrder(t, acc, "placeholder.example.com")

	authz, err := ac.db.GetAuthz([]byte(order.AuthzIDs[0]))
	if err != nil {
		t.Fatal(err)
	}
	token := authz.Challenges[0].Token

	key, err := ac.db.GetAccountKey(acc)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	keyAuth := token + "." + base64.RawURLEncoding.EncodeToString(thumb)

	var gotHost, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.Path
		w.Write([]byte(keyAuth))
	}))
	defer srv.Close()

	// The verifier fetches http://<identifier>/.well-known/..., so point the identifier at the test server
	host := mustHost(t, srv.URL)
	ac.db.UpdateAuthz([]byte(authz.ID), func(a *db.DBAuthz) error { a.Identifier.Value = host; return nil })

	chall, err := ac.InitiateChallenge([]byte(authz.ID+"00"), acc)
	if err != nil {
		t.Fatal(err)
	}

	if chall.Status != dtos.ChallengeStatusValid || chall.ValidatedTime == nil {
		t.Errorf("unexpected challenge: %+v", chall)
	}
	if gotPath != "/.well-known/acme-challenge/"+token || gotHost != host {
		t.Errorf("verifier requested host %q path %q", gotHost, gotPath)
	}

	latest, _ := ac.db.GetAuthz([]byte(authz.ID))
	if latest.Status != dtos.AuthzStatusValid || latest.Locked {
		t.Errorf("authz should be valid and unlocked: %+v", latest)
	}

	// With every authz valid, the order should have moved to ready
	got, err := ac.GetOrder([]byte(order.ID), acc)
	if err != nil || got.Status != dtos.OrderStatusReady {
		t.Errorf("order = %+v, %v; want ready", got, err)
	}

	// Challenges are single use
	if _, err := ac.InitiateChallenge([]byte(authz.ID+"00"), acc); err == nil {
		t.Error("expected re-initiating a valid challenge to fail")
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
