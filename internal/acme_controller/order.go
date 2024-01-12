package acme_controller

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

const orderExpiryTime = 2 * time.Minute

func (ac ACMEController) NewOrder(payload dtos.OrderCreateRequestDTO, accountID []byte) (*db.DBOrder, error) {
	// TODO: can we decide what orders the account is/isn't allowed to create?

	newId, err := GenerateID()
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	dbIdentifiers := make([]db.DBOrderIdentifier, len(payload.Identifiers))
	for i, identifier := range payload.Identifiers {
		if identifier.Value == "" {
			return nil, MalformedProblem(fmt.Sprintf("identifier index %d has an empty value", i))
		}

		// TODO: here, decide if a client is/isn't allowed to create a specific Value

		if identifier.Type != "dns" {
			return nil, MalformedProblem(fmt.Sprintf("identifier index %d had a type of %q, but the only supported type is \"dns\"", i, identifier.Type))
		}

		dbIdentifiers[i] = db.DBOrderIdentifier{
			Type:  identifier.Type,
			Value: identifier.Value,
		}
	}

	// TODO: validate these?
	nbf, err := time.Parse(time.RFC3339, payload.NotBefore)
	if err != nil {
		return nil, MalformedProblem("invalid NotBefore date format")
	}
	naft, err := time.Parse(time.RFC3339, payload.NotAfter)
	if err != nil {
		return nil, MalformedProblem("invalid NotAfter date format")
	}

	expires := time.Now().Add(orderExpiryTime)

	dbOrder := db.DBOrder{
		ID:        newId,
		AccountID: string(accountID),

		Status:  dtos.OrderStatusPending,
		Expires: expires.Unix(),

		NotBefore: nbf.Unix(),
		NotAfter:  naft.Unix(),

		Identifiers: dbIdentifiers,

		AuthzIDs: []string{}, // TODO generate AuthZs
	}

	err = ac.db.CreateOrder(dbOrder)
	if err != nil {
		return nil, InternalErrorProblem(err)
	}
	return &dbOrder, nil
}

func (ac ACMEController) GetOrder(orderID []byte, accountID []byte) (*db.DBOrder, error) {
	order, err := ac.db.GetOrder(orderID)
	if err != nil {
		if db.IsErrNotFound(err) {
			return nil, UnauthorizedProblem("")
		}
		return nil, InternalErrorProblem(err)
	}

	if order.AccountID != string(accountID) {
		return nil, UnauthorizedProblem("")
	}

	return order, nil
}

func (ac ACMEController) GetOrdersByAccountID(accountIDToQuery []byte, requestersAccountID []byte) ([]string, error) {
	if !bytes.Equal(accountIDToQuery, requestersAccountID) {
		return nil, UnauthorizedProblem("Account ID did not match requested account")
	}

	account, err := ac.db.GetAccount(accountIDToQuery)
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	orders := []string{}
	for _, order := range account.Orders {
		orders = append(orders, ac.linkCtrl.OrderPath(order).Abs())
	}

	return orders, nil
}

func (ac ACMEController) FinalizeOrder(orderID []byte, payload dtos.OrderFinalizeRequestDTO, requestersAccountID []byte) (*db.DBOrder, error) {
	order, err := ac.db.GetOrder([]byte(orderID))
	if err != nil {
		if db.IsErrNotFound(err) {
			return nil, UnauthorizedProblem("")
		}
		return nil, InternalErrorProblem(err)
	}

	if !bytes.Equal(requestersAccountID, []byte(order.AccountID)) {
		return nil, UnauthorizedProblem("")
	}

	derCSR, err := base64.URLEncoding.DecodeString(payload.CSRB64)
	if err != nil {
		return nil, BadCSRProblem("Invalid CSR Base64")
	}

	csr, err := x509.ParseCertificateRequest(derCSR)
	if err != nil {
		return nil, BadCSRProblem("Invalid CSR")
	}

	obtainResult, err := ac.acmeClient.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:       csr,
		NotBefore: time.Unix(order.NotBefore, 0),
		NotAfter:  time.Unix(order.NotAfter, 0),
		// TODO what to do with the other params in this struct?
	})
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	certID, err := GenerateID()
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	if len(obtainResult.Certificate) == 0 {
		return nil, InternalErrorProblem(fmt.Errorf("obtained certificate is empty: %v", obtainResult))
	}

	_, err = x509.ParseCertificate(obtainResult.Certificate)
	if err != nil {
		return nil, InternalErrorProblem(fmt.Errorf("obtained certificate is invalid: %v", err))
	}
	_, err = x509.ParseCertificate(obtainResult.IssuerCertificate)
	if len(obtainResult.IssuerCertificate) > 0 && err != nil {
		return nil, InternalErrorProblem(fmt.Errorf("obtained issuer certificate is inl"))
	}

	newCert := db.DBCertificate{
		ID:                certID,
		OrderID:           order.ID,
		AccountID:         order.AccountID,
		CertificateDER:    obtainResult.Certificate,
		IssuerCertificate: obtainResult.IssuerCertificate,
	}

	err = ac.db.CreateCertificate(newCert)
	if err != nil {
		return nil, InternalErrorProblem(err)
	}

	newOrder, err := ac.db.UpdateOrder([]byte(order.ID), func(orderToUpdate *db.DBOrder) error {
		orderToUpdate.CertificateID = certID
		orderToUpdate.Status = dtos.OrderStatusValid
		return nil
	})
	if err != nil {
		return nil, InternalErrorProblem(err)
	}
	return newOrder, nil
}
