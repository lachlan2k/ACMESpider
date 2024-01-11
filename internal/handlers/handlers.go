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
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/links"
	"github.com/lachlan2k/acmespider/internal/nonce"
	"github.com/lachlan2k/acmespider/internal/util"
)

type Handlers struct {
	Client    *lego.Client
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
		return echo.ErrMethodNotAllowed
	}
}

func (h Handlers) GetDirectory(c echo.Context) error {
	return c.JSON(http.StatusOK, h.LinkCtrl.DirectoryPath())
}

func (h Handlers) NewAccount(c echo.Context) error {
	payload, internalErr, userErr := getPayloadBoundBody[dtos.AccountRequestDTO](c)
	if internalErr != nil {
		return util.GenericServerErr(internalErr)
	}
	if userErr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, userErr.Error())
	}

	jwsHeaders, err := getProtectedHeader(c)
	if err != nil {
		return util.GenericServerErr(err)
	}
	jwk := jwsHeaders.JSONWebKey
	if jwk == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "JWK not provided")
	}

	newId, err := util.GenerateID()
	if err != nil {
		return util.GenericServerErr(err)
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
		return util.GenericServerErr(err)
	}

	c.Request().Header.Set("Location", h.LinkCtrl.AccountPath(newId).Abs())
	h.addLink(c, h.LinkCtrl.DirectoryPath().Abs(), "index")

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
		return util.GenericServerErr(err)
	}
	accountID, err := getAccountID(c)
	if err != nil {
		return util.GenericServerErr(err)
	}
	accIDParam := c.Param("accID")
	if accIDParam == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "accID is empty")
	}
	if string(accountID) != accIDParam {
		return echo.ErrUnauthorized
	}

	if len(payload) == 0 {
		// POST-as-GET
		acc, err := h.DB.GetAccount(accountID)
		if err != nil {
			if db.IsErrNotFound(err) {
				return echo.ErrNotFound
			}
			return util.GenericServerErr(err)
		}
		return c.JSON(http.StatusOK, h.dbAccountToDTO(acc))
	}

	var updateBody dtos.AccountRequestDTO
	err = json.Unmarshal(payload, &updateBody)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid body").SetInternal(err)
	}

	acc, err := h.DB.GetAccount(accountID)
	if err != nil {
		return util.GenericServerErr(err)
	}

	// There are two kinds of updates we can do
	// - deactivating the account: we just delete the account to do this, as we 401 anyway when an account isn't recognised
	// - updating Contact field
	if updateBody.Status == dtos.AccountStatusDeactivated {
		acc.Status = dtos.AccountStatusDeactivated
		err := h.DB.DeleteAccount(accountID)
		if err != nil {
			return util.GenericServerErr(err)
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
		return util.GenericServerErr(err)
	}

	// Update account
	return c.JSON(http.StatusOK, h.dbAccountToDTO(updatedAccount))
}

func (h Handlers) NotImplemented(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) NewOrder(c echo.Context) error {
	newOrderPayload, internalErr, userErr := getPayloadBoundBody[dtos.OrderCreateRequestDTO](c)
	if internalErr != nil {
		return util.GenericServerErr(internalErr)
	}
	if userErr != nil {
		return echo.ErrBadRequest
	}
	accountID, err := getAccountID(c)
	if err != nil {
		return util.GenericServerErr(err)
	}

	// TODO: can we decide what orders the account is/isn't allowed to create?
	newId, err := util.GenerateID()
	if err != nil {
		return util.GenericServerErr(err)
	}

	// TODO: validate paramters like nbf, na?

	dbIdentifiers := make([]db.DBOrderIdentifier, len(newOrderPayload.Identifiers))
	for i, identifier := range newOrderPayload.Identifiers {
		dbIdentifiers[i] = db.DBOrderIdentifier{
			Type:  identifier.Type,
			Value: identifier.Value,
		}
	}

	nbf, err := time.Parse(time.RFC3339, newOrderPayload.NotBefore)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid NotBefore date format")
	}
	naft, err := time.Parse(time.RFC3339, newOrderPayload.NotAfter)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid NotAfter date format")
	}

	dbOrder := db.DBOrder{
		ID:        newId,
		AccountID: string(accountID),

		Status:  dtos.OrderStatusPending,
		Expires: time.Now().Add(time.Hour).Unix(), // Todo more robust and goodness

		NotBefore: nbf.Unix(),
		NotAfter:  naft.Unix(),

		Identifiers: dbIdentifiers,

		AuthzIDs: []string{}, // TODO generate AuthZs

	}

	err = h.DB.CreateOrder(dbOrder)
	if err != nil {
		return util.GenericServerErr(err)
	}

	// TODO create authzs?

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
	return echo.ErrNotImplemented
}

func (h Handlers) GetOrdersByAccountID(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) FinalizeOrder(c echo.Context) error {
	finaliseRequestBody, internalErr, userErr := getPayloadBoundBody[dtos.OrderFinalizeRequestDTO](c)
	if internalErr != nil {
		return util.GenericServerErr(internalErr)
	}
	if userErr != nil {
		return echo.ErrBadRequest
	}

	// TODO access control
	derCSR, err := base64.URLEncoding.DecodeString(finaliseRequestBody.CSRB64)
	if err != nil {
		return echo.ErrBadRequest
	}

	csr, err := x509.ParseCertificateRequest(derCSR)
	if err != nil {
		return echo.ErrBadRequest
	}

	_, err = h.Client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR: csr,
		// TODO: grab NBF, etc, etc from from the order
	})
	if err != nil {
		return util.ServerError("failed to obtain certificate", err)
	}

	return echo.ErrNotImplemented
}

func (h Handlers) GetAuthorization(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) GetChallenge(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) GetCertificate(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) RevokeCert(c echo.Context) error {
	return echo.ErrNotImplemented
}
