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

func (ac ACMEController) makeChallengeID(authzID string, index int) string {
	return fmt.Sprintf("%s%02x", authzID, index)
}

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
	nbfT, err := dtos.TimeUnmarshalDTO(payload.NotBefore)
	if err != nil && payload.NotBefore != "" {
		return nil, MalformedProblem("invalid NotBefore date format")
	}
	naftT, err := dtos.TimeUnmarshalDTO(payload.NotAfter)
	if err != nil && payload.NotAfter != "" {
		return nil, MalformedProblem("invalid NotAfter date format")
	}
	// todo dry
	var nbf *int64 = nil
	if nbfT != nil {
		nbfu := nbfT.Unix()
		nbf = &nbfu
	}
	var naft *int64 = nil
	if naftT != nil {
		naftu := naftT.Unix()
		naft = &naftu
	}

	expires := time.Now().Add(orderExpiryTime)

	authzs := make([]db.DBAuthz, len(dbIdentifiers))
	authzIDs := make([]string, len(dbIdentifiers))

	for i, id := range dbIdentifiers {
		newAuthzID, err := GenerateID()
		if err != nil {
			return nil, InternalErrorProblem(fmt.Errorf("failed to generate ID for new authz: %v", err))
		}

		authzIDs[i] = newAuthzID

		challengeToken, err := GenerateChallengeToken()
		if err != nil {
			return nil, InternalErrorProblem(fmt.Errorf("failed to generate challenge token for authz: %v", err))
		}

		authzs[i] = db.DBAuthz{
			ID:         newAuthzID,
			OrderID:    newId,
			AccountID:  string(accountID),
			Status:     dtos.AuthzStatusPending,
			Identifier: id,
			Challenges: []db.DBAuthzChallenge{
				{
					ID:     ac.makeChallengeID(newAuthzID, 0),
					Type:   HTTP01ChallengeType,
					Token:  challengeToken,
					Status: dtos.AuthzStatusPending,
				},
			},
		}

		err = ac.db.CreateAuthz(authzs[i])
		if err != nil {
			return nil, InternalErrorProblem(fmt.Errorf("failed to write authz %d: %v", i, err))
		}
	}

	dbOrder := db.DBOrder{
		ID:        newId,
		AccountID: string(accountID),

		Status:  dtos.OrderStatusPending,
		Expires: expires.Unix(),

		NotBefore: nbf,
		NotAfter:  naft,

		Identifiers: dbIdentifiers,
		AuthzIDs:    authzIDs,
	}

	err = ac.db.CreateOrder(dbOrder)
	if err != nil {
		return nil, InternalErrorProblem(err)
	}
	return &dbOrder, nil
}

func (ac ACMEController) GetOrder(orderID []byte, accountID []byte) (*db.DBOrder, error) {
	ac.recomputeOrderStatus([]byte(orderID))

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

	derCSR, err := base64.RawURLEncoding.DecodeString(payload.CSRB64)
	if err != nil {
		return nil, BadCSRProblem("Invalid CSR Base64")
	}

	csr, err := x509.ParseCertificateRequest(derCSR)
	if err != nil {
		return nil, BadCSRProblem("Invalid CSR")
	}

	// Check all authz are complete
	for i, authzID := range order.AuthzIDs {
		authz, err := ac.db.GetAuthz([]byte(authzID))
		if err != nil {
			return nil, InternalErrorProblem(err)
		}
		if authz.Status != dtos.AuthzStatusValid {
			return nil, OrderNotReadyProblem(fmt.Sprintf("Authz %d was not valid, current status is %s", i, authz.Status))
		}
	}

	nbf := time.Time{}
	if order.NotBefore != nil {
		nbf = timeUnmarshalDB(*order.NotBefore)
	}
	naft := time.Time{}
	if order.NotAfter != nil {
		naft = timeUnmarshalDB(*order.NotAfter)
	}

	obtainResult, err := ac.acmeClient.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:       csr,
		NotBefore: nbf,
		NotAfter:  naft,
		Bundle:    true,
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

	newCert := db.DBCertificate{
		ID:          certID,
		OrderID:     order.ID,
		AccountID:   order.AccountID,
		Certificate: obtainResult.Certificate,
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

func (ac ACMEController) GetAuthorization(authzID []byte, requesterAccountID []byte) (*db.DBAuthz, error) {
	authz, err := ac.db.GetAuthz(authzID)
	if err != nil {
		if db.IsErrNotFound(err) {
			return nil, UnauthorizedProblem("")
		}
		return nil, InternalErrorProblem(err)
	}

	if !bytes.Equal(requesterAccountID, []byte(authz.AccountID)) {
		return nil, UnauthorizedProblem("")
	}

	return authz, nil
}
