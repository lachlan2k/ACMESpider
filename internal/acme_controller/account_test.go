package acme_controller

import (
	"net/http"
	"testing"

	"github.com/lachlan2k/acmespider/internal/dtos"
)

func TestValidateContacts(t *testing.T) {
	tests := []struct {
		name     string
		contacts []string
		wantType string // empty means valid
	}{
		{"none", nil, ""},
		{"empty list", []string{}, ""},
		{"one mailto", []string{"mailto:admin@example.com"}, ""},
		{"several mailtos", []string{"mailto:a@example.com", "mailto:b@example.org"}, ""},
		{"upper case scheme", []string{"MAILTO:admin@example.com"}, ""},

		{"not a url", []string{"not a url"}, invalidContactErr},
		{"empty string", []string{""}, invalidContactErr},
		{"bare address", []string{"admin@example.com"}, invalidContactErr},
		{"mailto without address", []string{"mailto:"}, invalidContactErr},
		{"mailto with invalid address", []string{"mailto:nope"}, invalidContactErr},
		{"mailto with display name", []string{"mailto:Admin <admin@example.com>"}, invalidContactErr},
		{"mailto with hfields", []string{"mailto:admin@example.com?subject=hi"}, invalidContactErr},
		{"mailto with several addresses", []string{"mailto:a@example.com,b@example.com"}, invalidContactErr},
		{"mailto with fragment", []string{"mailto:admin@example.com#x"}, invalidContactErr},
		{"one bad among good", []string{"mailto:admin@example.com", "mailto:nope"}, invalidContactErr},

		{"http scheme", []string{"http://example.com/contact"}, unsupportedContactErr},
		{"tel scheme", []string{"tel:+1555123456"}, unsupportedContactErr},
		{"unsupported among good", []string{"mailto:admin@example.com", "tel:+1555123456"}, unsupportedContactErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContacts(tt.contacts)
			if tt.wantType == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			expectProblem(t, err, tt.wantType, http.StatusBadRequest)
		})
	}
}

func TestNewAccountRejectsInvalidContacts(t *testing.T) {
	ac := newTestCtrl(t)
	key, _ := ac.db.GetAccountKey(ac.newTestAccount(t))

	_, err := ac.NewAccount(dtos.AccountRequestDTO{Contact: []string{"tel:+1555123456"}}, *key)
	expectProblem(t, err, unsupportedContactErr, http.StatusBadRequest)

	_, err = ac.NewAccount(dtos.AccountRequestDTO{Contact: []string{"mailto:nope"}}, *key)
	expectProblem(t, err, invalidContactErr, http.StatusBadRequest)

	acc, err := ac.NewAccount(dtos.AccountRequestDTO{Contact: []string{"mailto:ok@example.com"}}, *key)
	if err != nil || len(acc.Contact) != 1 {
		t.Fatalf("valid contacts rejected: %v", err)
	}
}

func TestUpdateAccountContacts(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)

	updated, err := ac.UpdateAccount(acc, acc, dtos.AccountRequestDTO{Contact: []string{"mailto:new@example.com"}})
	if err != nil || len(updated.Contact) != 1 || updated.Contact[0] != "mailto:new@example.com" {
		t.Fatalf("got %+v, %v", updated, err)
	}

	// Rejected updates must leave the existing contacts alone
	_, err = ac.UpdateAccount(acc, acc, dtos.AccountRequestDTO{Contact: []string{"http://example.com"}})
	expectProblem(t, err, unsupportedContactErr, http.StatusBadRequest)
	_, err = ac.UpdateAccount(acc, acc, dtos.AccountRequestDTO{Contact: []string{"mailto:a@example.com?subject=x"}})
	expectProblem(t, err, invalidContactErr, http.StatusBadRequest)

	got, _ := ac.GetAccount(acc, acc)
	if len(got.Contact) != 1 || got.Contact[0] != "mailto:new@example.com" {
		t.Errorf("contacts changed by rejected update: %v", got.Contact)
	}

	// Omitting contact leaves them as they were
	if _, err := ac.UpdateAccount(acc, acc, dtos.AccountRequestDTO{}); err != nil {
		t.Fatal(err)
	}
	got, _ = ac.GetAccount(acc, acc)
	if len(got.Contact) != 1 {
		t.Errorf("contacts lost: %v", got.Contact)
	}
}

func TestDeactivationDoesNotValidateContacts(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)

	// A deactivation request only cares about the status
	updated, err := ac.UpdateAccount(acc, acc, dtos.AccountRequestDTO{Status: dtos.AccountStatusDeactivated, Contact: []string{"tel:+1"}})
	if err != nil || updated.Status != dtos.AccountStatusDeactivated {
		t.Fatalf("got %+v, %v", updated, err)
	}
}
