package acme_controller

import (
	"bytes"
	"fmt"
	"net/mail"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

func validateContacts(contacts []string) error {
	// RFC 8555 7.3 says we _SHOULD_ validate contacts
	// and if we do validate, we _MUST_ support mailto:
	// ...and we _SHOULD_ reject hfields.
	for i, contact := range contacts {
		u, err := url.Parse(contact)
		if err != nil || u.Scheme == "" {
			return InvalidContactProblem(fmt.Sprintf("contact %d is not a valid URL", i))
		}

		if !strings.EqualFold(u.Scheme, "mailto") {
			return UnsupportedContactProblem(fmt.Sprintf("contact %d uses the %q scheme, but only mailto: is supported", i, u.Scheme))
		}

		addr := u.Opaque
		if addr == "" || u.RawQuery != "" || strings.Contains(contact, "?") || u.Fragment != "" || strings.Contains(addr, ",") {
			return InvalidContactProblem(fmt.Sprintf("contact %d must be a mailto: URL with a single address and no header fields", i))
		}
		if parsed, err := mail.ParseAddress(addr); err != nil || parsed.Address != addr {
			return InvalidContactProblem(fmt.Sprintf("contact %d does not contain a valid email address", i))
		}
	}
	return nil
}

func (ac ACMEController) NewAccount(payload dtos.AccountRequestDTO, jwk jose.JSONWebKey) (*db.DBAccount, error) {
	if err := validateContacts(payload.Contact); err != nil {
		return nil, err
	}

	newId, err := GenerateID()

	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	accToCreate := db.DBAccount{
		ID:                   newId,
		Status:               dtos.AccountStatusValid,
		Contact:              payload.Contact,
		TermsOfServiceAgreed: payload.TermsOfServiceAgreed,
		Orders:               []string{},
	}

	err = ac.db.CreateAccount(accToCreate, &jwk)
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	return &accToCreate, err
}

func (ac ACMEController) GetAccount(accountIDToQuery []byte, requestAccountID []byte) (*db.DBAccount, error) {
	if !bytes.Equal(accountIDToQuery, requestAccountID) {
		return nil, UnauthorizedProblem("Account ID did not match requested account")
	}

	account, err := ac.db.GetAccount(accountIDToQuery)
	if err != nil {
		if db.IsErrNotFound(err) {
			// Not sure how we'd get here, given that account ID needs to be tied to a valid KID
			return nil, UnauthorizedProblem("")
		}
		return nil, InternalErrorProblem(err)
	}
	return account, nil
}

func (ac ACMEController) GetAccountKey(accountID []byte) (*jose.JSONWebKey, error) {
	return ac.db.GetAccountKey(accountID)
}

func (ac ACMEController) UpdateAccount(accountIDToQuery []byte, requestAccountID []byte, payload dtos.AccountRequestDTO) (*db.DBAccount, error) {
	if !bytes.Equal(accountIDToQuery, requestAccountID) {
		return nil, UnauthorizedProblem("Account ID did not match requested account")
	}

	if payload.Status != dtos.AccountStatusDeactivated {
		if err := validateContacts(payload.Contact); err != nil {
			return nil, err
		}
	}

	acc, err := ac.db.GetAccount(accountIDToQuery)
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	// There are two kinds of updates we can do
	// - deactivating the account: we just delete the account to do this, as we 401 anyway when an account isn't recognised
	// - updating Contact field
	if payload.Status == dtos.AccountStatusDeactivated {
		acc.Status = dtos.AccountStatusDeactivated
		err := ac.db.DeleteAccount(accountIDToQuery)
		if err != nil {
			return nil, InternalErrorProblem(err)
		}
		return acc, nil
	}

	updatedAccount, err := ac.db.UpdateAccount(accountIDToQuery, func(dbAcc *db.DBAccount) error {
		if payload.Contact != nil {
			dbAcc.Contact = payload.Contact
		}
		return nil
	})
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	return updatedAccount, nil
}
