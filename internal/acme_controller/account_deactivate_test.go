package acme_controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/links"
)

// A deactivated account's key must no longer be retrievable, since the KID lookup
// used to validate request signatures goes through GetAccountKey.
func TestDeactivatedAccountKeyIsNotRetrievable(t *testing.T) {
	d, err := db.NewBoltDb(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Seed(); err != nil {
		t.Fatal(err)
	}
	ctrl := New(d, nil, links.LinkController{BaseURL: "https://example.com/acme"})

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := ctrl.NewAccount(dtos.AccountRequestDTO{}, jose.JSONWebKey{Key: priv.Public()})
	if err != nil {
		t.Fatal(err)
	}
	id := []byte(acc.ID)

	if _, err := ctrl.GetAccountKey(id); err != nil {
		t.Fatalf("key should exist before deactivation: %v", err)
	}

	if _, err := ctrl.UpdateAccount(id, id, dtos.AccountRequestDTO{Status: dtos.AccountStatusDeactivated}); err != nil {
		t.Fatal(err)
	}

	if _, err := ctrl.GetAccountKey(id); !db.IsErrNotFound(err) {
		t.Fatalf("expected ErrNotFound for deactivated account's key, got %v", err)
	}
}
