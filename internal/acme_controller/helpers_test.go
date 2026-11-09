package acme_controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/links"
)

// newTestCtrl returns a controller backed by a fresh BoltDB. The lego client is nil,
// so anything that would actually talk to an ACME authority can't be exercised.
func newTestCtrl(t *testing.T) *ACMEController {
	t.Helper()

	d, err := db.NewBoltDb(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Seed(); err != nil {
		t.Fatal(err)
	}
	return New(d, nil, links.LinkController{BaseURL: "https://example.com/acme"})
}

func (ac *ACMEController) newTestAccount(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := ac.NewAccount(dtos.AccountRequestDTO{}, jose.JSONWebKey{Key: priv.Public()})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(acc.ID)
}

func (ac *ACMEController) newTestOrder(t *testing.T, accountID []byte, domains ...string) *db.DBOrder {
	t.Helper()

	ids := make([]dtos.OrderIdentifierDTO, len(domains))
	for i, d := range domains {
		ids[i] = dtos.OrderIdentifierDTO{Type: "dns", Value: d}
	}
	order, err := ac.NewOrder(dtos.OrderCreateRequestDTO{Identifiers: ids}, accountID)
	if err != nil {
		t.Fatal(err)
	}
	return order
}

func (ac *ACMEController) markAuthzValid(t *testing.T, authzID string) {
	t.Helper()

	_, err := ac.db.UpdateAuthz([]byte(authzID), func(a *db.DBAuthz) error {
		a.Status = dtos.AuthzStatusValid
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func problemOf(t *testing.T, err error) *ProblemDetails {
	t.Helper()

	var pd *ProblemDetails
	if !errors.As(err, &pd) {
		t.Fatalf("expected ProblemDetails, got %T: %v", err, err)
	}
	return pd
}

func expectProblem(t *testing.T, err error, wantType string, wantStatus int) {
	t.Helper()

	pd := problemOf(t, err)
	if pd.Type != wantType || pd.HTTPStatus != wantStatus {
		t.Fatalf("got (%s, %d: %q), want (%s, %d)", pd.Type, pd.HTTPStatus, pd.Detail, wantType, wantStatus)
	}
}

func expectUnauthorized(t *testing.T, err error) {
	t.Helper()
	expectProblem(t, err, unauthorizedErr, http.StatusForbidden)
}
