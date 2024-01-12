package handlers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/links"
	"github.com/lachlan2k/acmespider/internal/nonce"
	"github.com/lachlan2k/acmespider/internal/util"
)

type Handlers struct {
	Client    *lego.Client
	AcmeCtrl  *acme_controller.ACMEController
	NonceCtrl nonce.NonceController
	LinkCtrl  links.LinkController
	DB        db.DB
}

func (h Handlers) addLink(c echo.Context, url string, rel string) {
	headers := c.Response().Header()
	headers.Set("Link", fmt.Sprintf("<%s>;rel=%q", url, rel))
}

func (h Handlers) GetNonce(c echo.Context) error {
	// https://datatracker.ietf.org/doc/html/rfc8555#section-7.2
	// The nonce itself is added by middleware

	switch c.Request().Method {
	case http.MethodGet:
		return c.NoContent(http.StatusNoContent)
	case http.MethodHead:
		return c.NoContent(http.StatusOK)
	default:
		return acme_controller.MethodNotAllowed()
	}
}

func (h Handlers) GetDirectory(c echo.Context) error {
	return c.JSON(http.StatusOK, h.LinkCtrl.DirectoryPath())
}

func (h Handlers) NewAccount(c echo.Context) error {
	payload, internalErr, userErr := getPayloadBoundBody[dtos.AccountRequestDTO](c)
	if internalErr != nil {
		return acme_controller.InternalErrorProblem(internalErr)
	}
	if userErr != nil {
		return acme_controller.MalformedProblem("Invalid body")
	}

	jwsHeaders, err := getProtectedHeader(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	jwk := jwsHeaders.JSONWebKey
	if jwk == nil {
		return acme_controller.MalformedProblem("JWK not provided")
	}

	newId, err := util.GenerateID()
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	accToCreate := db.DBAccount{
		ID:                   newId,
		Status:               dtos.AccountStatusValid,
		Contact:              payload.Contact,
		TermsOfServiceAgreed: payload.TermsOfServiceAgreed,
		Orders:               []string{},
	}

	err = h.DB.CreateAccount(accToCreate, jwk)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	c.Request().Header.Set("Location", h.LinkCtrl.AccountPath(newId).Abs())

	return c.JSON(http.StatusCreated, h.dbAccountToDTO(&accToCreate))
}

func (h Handlers) dbAccountToDTO(acc *db.DBAccount) dtos.AccountResponseDTO {
	return dtos.AccountResponseDTO{
		Status:               acc.Status,
		Contact:              acc.Contact,
		OrdersURL:            h.LinkCtrl.AccountOrdersPath(acc.ID).Abs(),
		TermsOfServiceAgreed: acc.TermsOfServiceAgreed,
	}
}

func (h Handlers) GetOrUpdateAccount(c echo.Context) error {
	payload, err := getPayloadBody(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	accIDParam := c.Param(h.LinkCtrl.AccountIDParam())
	if accIDParam == "" {
		return acme_controller.MalformedProblem("accID is empty")
	}
	if string(accountID) != accIDParam {
		return acme_controller.UnauthorizedProblem("")
	}

	if len(payload) == 0 {
		// POST-as-GET
		acc, err := h.DB.GetAccount(accountID)
		if err != nil {
			if db.IsErrNotFound(err) {
				// Not sure how we'd get here, given that account ID needs to be tied to a valid KID
				return acme_controller.UnauthorizedProblem("")
			}
			return acme_controller.InternalErrorProblem(err)
		}
		return c.JSON(http.StatusOK, h.dbAccountToDTO(acc))
	}

	var updateBody dtos.AccountRequestDTO
	err = json.Unmarshal(payload, &updateBody)
	if err != nil {
		return acme_controller.MalformedProblem("Invalid body")
	}

	acc, err := h.DB.GetAccount(accountID)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	// There are two kinds of updates we can do
	// - deactivating the account: we just delete the account to do this, as we 401 anyway when an account isn't recognised
	// - updating Contact field
	if updateBody.Status == dtos.AccountStatusDeactivated {
		acc.Status = dtos.AccountStatusDeactivated
		err := h.DB.DeleteAccount(accountID)
		if err != nil {
			return acme_controller.InternalErrorProblem(err)
		}

		return c.JSON(http.StatusOK, h.dbAccountToDTO(acc))
	}

	updatedAccount, err := h.DB.UpdateAccount(accountID, func(dbAcc *db.DBAccount) error {
		if updateBody.Contact != nil {
			dbAcc.Contact = updateBody.Contact
		}
		return nil
	})
	if err != nil {
		return acme_controller.InternalErrorProblem(err)

	}

	// Update account
	return c.JSON(http.StatusOK, h.dbAccountToDTO(updatedAccount))
}

func (h Handlers) ErrorHandler(app *echo.Echo) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		probErr, ok := err.(*acme_controller.ProblemDetails)
		if !ok {
			app.DefaultHTTPErrorHandler(err, c)
			return
		}

		c.JSON(probErr.HTTPStatus, probErr)
	}
}

func (h Handlers) NotImplemented(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) NewOrder(c echo.Context) error {
	newOrderPayload, internalErr, userErr := getPayloadBoundBody[dtos.OrderCreateRequestDTO](c)
	if internalErr != nil {
		return acme_controller.InternalErrorProblem(internalErr)

	}
	if userErr != nil {
		return acme_controller.MalformedProblem("Invalid body")
	}
	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	// TODO: can we decide what orders the account is/isn't allowed to create?
	newId, err := util.GenerateID()
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	dbIdentifiers := make([]db.DBOrderIdentifier, len(newOrderPayload.Identifiers))
	for i, identifier := range newOrderPayload.Identifiers {
		if identifier.Value == "" {
			return acme_controller.MalformedProblem(fmt.Sprintf("identifier index %d has an empty value", i))
		}

		// TODO: here, decide if a client is/isn't allowed to create a specific Value

		if identifier.Type != "dns" {
			return acme_controller.MalformedProblem(fmt.Sprintf("identifier index %d had a type of %q, but the only supported type is \"dns\"", i, identifier.Type))
		}

		dbIdentifiers[i] = db.DBOrderIdentifier{
			Type:  identifier.Type,
			Value: identifier.Value,
		}
	}

	nbf, err := time.Parse(time.RFC3339, newOrderPayload.NotBefore)
	if err != nil {
		return acme_controller.MalformedProblem("invalid NotBefore date format")
	}
	naft, err := time.Parse(time.RFC3339, newOrderPayload.NotAfter)
	if err != nil {
		return acme_controller.MalformedProblem("invalid NotAfter date format")
	}

	expires := time.Now().Add(2 * time.Minute)

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

	err = h.DB.CreateOrder(dbOrder)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	// TODO create authzs?
	c.Request().Header.Set("Location", h.LinkCtrl.OrderPath(newId).Abs())

	return c.JSON(http.StatusCreated, dtos.OrderResponseDTO{
		Status:            dbOrder.Status,
		Expires:           time.Unix(dbOrder.Expires, 0).Format(time.RFC3339),
		NotBefore:         nbf.Format(time.RFC3339),
		NotAfter:          naft.Format(time.RFC3339),
		Identifiers:       newOrderPayload.Identifiers,
		AuthorizationURLs: []string{}, // todo
		FinalizeURL:       h.LinkCtrl.FinalizeOrderPath(newId).Abs(),
		CertificateURL:    "",
	})
}

func (h Handlers) GetOrder(c echo.Context) error {
	orderID := c.Param(h.LinkCtrl.OrderIDParam())
	if orderID == "" {
		return acme_controller.MalformedProblem("no order ID")
	}
	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	order, err := h.DB.GetOrder([]byte(orderID))
	if err != nil {
		if db.IsErrNotFound(err) {
			return acme_controller.UnauthorizedProblem("")
		}
		return acme_controller.InternalErrorProblem(err)
	}

	if order.AccountID != string(accountID) {
		return acme_controller.UnauthorizedProblem("")
	}

	return c.JSON(http.StatusOK, h.dbOrderToDTO(order))
}

func (h Handlers) GetOrdersByAccountID(c echo.Context) error {
	paramAccountID := c.Param(h.LinkCtrl.AccountIDParam())
	if paramAccountID == "" {
		return acme_controller.MalformedProblem("no account ID")
	}
	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	if string(accountID) != paramAccountID {
		return acme_controller.UnauthorizedProblem("")
	}

	account, err := h.DB.GetAccount(accountID)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	orders := []string{}
	for _, order := range account.Orders {
		orders = append(orders, h.LinkCtrl.OrderPath(order).Abs())
	}

	return c.JSON(http.StatusOK, dtos.OrdersListResponseDTO{
		Orders: orders,
	})
}

func (h Handlers) FinalizeOrder(c echo.Context) error {
	finaliseRequestBody, internalErr, userErr := getPayloadBoundBody[dtos.OrderFinalizeRequestDTO](c)
	if internalErr != nil {
		return acme_controller.InternalErrorProblem(internalErr)
	}
	if userErr != nil {
		return acme_controller.MalformedProblem("Invalid body")
	}

	orderID := c.Param(h.LinkCtrl.OrderIDParam())
	if orderID == "" {
		return acme_controller.MalformedProblem("no order ID")
	}

	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	order, err := h.DB.GetOrder([]byte(orderID))
	if err != nil {
		if db.IsErrNotFound(err) {
			return acme_controller.UnauthorizedProblem("")
		}
		return acme_controller.InternalErrorProblem(err)
	}

	if string(accountID) != order.AccountID {
		return acme_controller.UnauthorizedProblem("")
	}

	derCSR, err := base64.URLEncoding.DecodeString(finaliseRequestBody.CSRB64)
	if err != nil {
		return acme_controller.MalformedProblem("Invalid CSR Base64")
	}

	csr, err := x509.ParseCertificateRequest(derCSR)
	if err != nil {
		return acme_controller.MalformedProblem("Invalid CSR")
	}

	obtainResult, err := h.Client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:       csr,
		NotBefore: time.Unix(order.NotBefore, 0),
		NotAfter:  time.Unix(order.NotAfter, 0),
		// TODO what to do with the other params in this struct?
	})
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	certID, err := util.GenerateID()
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	if len(obtainResult.Certificate) == 0 {
		return acme_controller.InternalErrorProblem(fmt.Errorf("obtained certificate is empty: %v", obtainResult))
	}

	_, err = x509.ParseCertificate(obtainResult.Certificate)
	if err != nil {
		return acme_controller.InternalErrorProblem(fmt.Errorf("obtained certificate is invalid: %v", err))
	}
	_, err = x509.ParseCertificate(obtainResult.IssuerCertificate)
	if len(obtainResult.IssuerCertificate) > 0 && err != nil {
		return acme_controller.InternalErrorProblem(fmt.Errorf("obtained issuer certificate is inl"))
	}

	newCert := db.DBCertificate{
		ID:                certID,
		OrderID:           order.ID,
		AccountID:         order.AccountID,
		CertificateDER:    obtainResult.Certificate,
		IssuerCertificate: obtainResult.IssuerCertificate,
	}

	err = h.DB.CreateCertificate(newCert)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	newOrder, err := h.DB.UpdateOrder([]byte(order.ID), func(orderToUpdate *db.DBOrder) error {
		orderToUpdate.CertificateID = certID
		orderToUpdate.Status = dtos.OrderStatusValid
		return nil
	})
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	c.Request().Header.Set("Location", h.LinkCtrl.OrderPath(order.ID).Abs())

	return c.JSON(http.StatusOK, h.dbOrderToDTO(newOrder))
}

func (h Handlers) dbOrderToDTO(order *db.DBOrder) dtos.OrderResponseDTO {
	identifiers := make([]dtos.OrderIdentifierDTO, len(order.Identifiers))
	for i, identifier := range order.Identifiers {
		identifiers[i] = dtos.OrderIdentifierDTO{
			Type:  identifier.Type,
			Value: identifier.Value,
		}
	}

	authzURLs := make([]string, len(order.AuthzIDs))
	for i, authzID := range order.AuthzIDs {
		authzURLs[i] = h.LinkCtrl.AuthzPath(authzID).Abs()
	}

	return dtos.OrderResponseDTO{
		Status:            order.Status,
		Expires:           time.Unix(order.Expires, 0).Format(time.RFC3339),
		NotBefore:         time.Unix(order.NotBefore, 0).Format(time.RFC3339),
		NotAfter:          time.Unix(order.NotAfter, 0).Format(time.RFC3339),
		Identifiers:       identifiers,
		AuthorizationURLs: authzURLs,
		FinalizeURL:       h.LinkCtrl.FinalizeOrderPath(order.ID).Abs(),
		CertificateURL:    h.LinkCtrl.CertPath(order.CertificateID).Abs(),
	}
}

func (h Handlers) GetAuthorization(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) GetChallenge(c echo.Context) error {
	payloadBody, err := getPayloadBody(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	if string(payloadBody) != "{}" {
		return acme_controller.MalformedProblem("Expected empty JSON object ({}) for payload")
	}

	return echo.ErrNotImplemented
}

func (h Handlers) GetCertificate(c echo.Context) error {
	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	certID := c.Param(h.LinkCtrl.CertIDParam())
	if len(certID) == 0 {
		return acme_controller.MalformedProblem("Empty certificate ID")
	}

	pemOutput, err := h.AcmeCtrl.GetCertificate(accountID, []byte(certID))
	if err != nil {
		return err
	}

	return c.Blob(http.StatusOK, "application/pem-certificate-chain", pemOutput)
}

func (h Handlers) RevokeCert(c echo.Context) error {
	_, internalErr, userErr := getPayloadBoundBody[dtos.RevokeCertRequestDTO](c)
	if internalErr != nil {
		return acme_controller.InternalErrorProblem(internalErr)
	}
	if userErr != nil {
		return acme_controller.MalformedProblem("Invalid body")
	}

	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	certID := c.Param(h.LinkCtrl.CertIDParam())
	if len(certID) == 0 {
		return acme_controller.MalformedProblem("Empty certificate ID")
	}

	cert, err := h.DB.GetCertificate([]byte(certID))
	if err != nil {
		if db.IsErrNotFound(err) {
			return acme_controller.UnauthorizedProblem("")
		}
		return acme_controller.InternalErrorProblem(err)
	}
	if cert == nil {
		return acme_controller.UnauthorizedProblem("")
	}
	if cert.AccountID != string(accountID) {
		return acme_controller.UnauthorizedProblem("")
	}

	return echo.ErrNotImplemented
}
