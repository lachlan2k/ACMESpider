package handlers

import (
	"reflect"
	"testing"

	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/links"
)

func testHandlers() Handlers {
	return Handlers{LinkCtrl: links.LinkController{BaseURL: "https://example.com/acme"}}
}

func ptr[T any](v T) *T { return &v }

func TestDBOrderToDTO(t *testing.T) {
	h := testHandlers()

	order := &db.DBOrder{
		ID:            "o1",
		Status:        dtos.OrderStatusValid,
		Expires:       1700000000,
		NotBefore:     ptr(int64(1700000100)),
		NotAfter:      ptr(int64(1700000200)),
		Identifiers:   []db.DBOrderIdentifier{{Type: "dns", Value: "a.example.com"}},
		CertificateID: "c1",
		AuthzIDs:      []string{"z1", "z2"},
	}

	got := h.dbOrderToDTO(order)

	if got.Status != "valid" || got.Expires != time64ToString(1700000000) {
		t.Errorf("unexpected status/expires: %+v", got)
	}
	if got.NotBefore != time64ToString(1700000100) || got.NotAfter != time64ToString(1700000200) {
		t.Errorf("unexpected nbf/naf: %q %q", got.NotBefore, got.NotAfter)
	}
	if !reflect.DeepEqual(got.Identifiers, []dtos.OrderIdentifierDTO{{Type: "dns", Value: "a.example.com"}}) {
		t.Errorf("unexpected identifiers: %+v", got.Identifiers)
	}
	wantAuthz := []string{"https://example.com/acme/authz/z1", "https://example.com/acme/authz/z2"}
	if !reflect.DeepEqual(got.AuthorizationURLs, wantAuthz) {
		t.Errorf("got %v, want %v", got.AuthorizationURLs, wantAuthz)
	}
	if got.FinalizeURL != "https://example.com/acme/order/o1/finalize" {
		t.Errorf("unexpected finalize URL %q", got.FinalizeURL)
	}
	if got.CertificateURL != "https://example.com/acme/certificate/c1" {
		t.Errorf("unexpected cert URL %q", got.CertificateURL)
	}
	if got.Error != nil {
		t.Errorf("unexpected error: %+v", got.Error)
	}
}

func TestDBOrderToDTOOptionalFields(t *testing.T) {
	h := testHandlers()

	got := h.dbOrderToDTO(&db.DBOrder{ID: "o1", ErrorID: "err-123"})

	if got.NotBefore != "" || got.NotAfter != "" {
		t.Errorf("expected empty nbf/naf, got %q %q", got.NotBefore, got.NotAfter)
	}
	if got.Identifiers == nil || got.AuthorizationURLs == nil {
		t.Error("slices should be non-nil so they serialise as []")
	}
	if got.Error == nil || got.Error.HTTPStatus != 500 || got.Error.Detail != "Error ID err-123" {
		t.Errorf("unexpected error problem: %+v", got.Error)
	}
}

func TestDBAuthzToDTO(t *testing.T) {
	h := testHandlers()

	authz := &db.DBAuthz{
		ID:                 "z1",
		Status:             dtos.AuthzStatusValid,
		ExpireValidityTime: ptr(int64(1700000000)),
		Identifier:         db.DBOrderIdentifier{Type: "dns", Value: "a.example.com"},
		Challenges: []db.DBAuthzChallenge{
			{ID: "ch1", Type: "http-01", Token: "tok", Status: dtos.ChallengeStatusValid, ValidatedTime: ptr(int64(1700000050))},
			{ID: "ch2", Type: "http-01", Token: "tok2", Status: dtos.ChallengeStatusPending},
		},
	}

	got := h.dbAuthzToDTO(authz)

	if got.Status != "valid" || got.Expires != time64ToString(1700000000) {
		t.Errorf("unexpected status/expires: %+v", got)
	}
	if got.Identifier != (dtos.AuthzIdentifierDTO{Type: "dns", Value: "a.example.com"}) {
		t.Errorf("unexpected identifier: %+v", got.Identifier)
	}
	if len(got.Challenges) != 2 {
		t.Fatalf("got %d challenges", len(got.Challenges))
	}
	if got.Challenges[0].URL != "https://example.com/acme/chall/ch1" || got.Challenges[0].ValidatedTime != time64ToString(1700000050) {
		t.Errorf("unexpected challenge 0: %+v", got.Challenges[0])
	}
	if got.Challenges[1].ValidatedTime != "" || got.Challenges[1].Token != "tok2" {
		t.Errorf("unexpected challenge 1: %+v", got.Challenges[1])
	}

	noExpiry := h.dbAuthzToDTO(&db.DBAuthz{})
	if noExpiry.Expires != "" {
		t.Errorf("expected empty expiry, got %q", noExpiry.Expires)
	}
}
