package acme_controller

import (
	"bytes"

	"github.com/go-jose/go-jose/v3"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

func (ac ACMEController) NewAccount(payload dtos.AccountRequestDTO, jwk jose.JSONWebKey) (*db.DBAccount, error) {
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
