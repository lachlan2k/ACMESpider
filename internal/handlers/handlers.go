package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/links"
	"github.com/lachlan2k/acmespider/internal/nonce"
)

type Handlers struct {
	AcmeCtrl  *acme_controller.ACMEController
	NonceCtrl nonce.NonceController
	LinkCtrl  links.LinkController
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
	payload, err := getPayloadBoundBody[dtos.AccountRequestDTO](c)
	if err != nil {
		return err
	}

	jwsHeaders, err := getProtectedHeader(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	jwk := jwsHeaders.JSONWebKey
	if jwk == nil {
		return acme_controller.MalformedProblem("JWK not provided")
	}

	newAcc, err := h.AcmeCtrl.NewAccount(*payload, *jwk)
	if err != nil {
		return err
	}

	c.Request().Header.Set("Location", h.LinkCtrl.AccountPath(newAcc.ID).Abs())

	return c.JSON(http.StatusCreated, h.dbAccountToDTO(newAcc))
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

	if len(payload) == 0 {
		// POST-as-GET
		acc, err := h.AcmeCtrl.GetAccount(accountID, []byte(accIDParam))
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, h.dbAccountToDTO(acc))
	}

	var updateBody dtos.AccountRequestDTO
	err = json.Unmarshal(payload, &updateBody)
	if err != nil {
		return acme_controller.MalformedProblem("Invalid JSON")
	}

	acc, err := h.AcmeCtrl.UpdateAccount(accountID, []byte(accIDParam), updateBody)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, h.dbAccountToDTO(acc))
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
	newOrderPayload, err := getPayloadBoundBody[dtos.OrderCreateRequestDTO](c)
	if err != nil {
		return err
	}

	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	newOrder, err := h.AcmeCtrl.NewOrder(*newOrderPayload, accountID)
	if err != nil {
		return err
	}

	// TODO create authzs?
	c.Request().Header.Set("Location", h.LinkCtrl.OrderPath(newOrder.ID).Abs())

	return c.JSON(http.StatusCreated, h.dbOrderToDTO(newOrder))
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

	order, err := h.AcmeCtrl.GetOrder([]byte(orderID), accountID)
	if err != nil {
		return err
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

	orders, err := h.AcmeCtrl.GetOrdersByAccountID([]byte(paramAccountID), accountID)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, dtos.OrdersListResponseDTO{
		Orders: orders,
	})
}

func (h Handlers) FinalizeOrder(c echo.Context) error {
	payload, err := getPayloadBoundBody[dtos.OrderFinalizeRequestDTO](c)
	if err != nil {
		return err
	}

	orderID := c.Param(h.LinkCtrl.OrderIDParam())
	if orderID == "" {
		return acme_controller.MalformedProblem("no order ID")
	}

	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	updatedOrder, err := h.AcmeCtrl.FinalizeOrder([]byte(orderID), *payload, accountID)
	if err != nil {
		return err
	}

	c.Request().Header.Set("Location", h.LinkCtrl.OrderPath(updatedOrder.ID).Abs())

	return c.JSON(http.StatusOK, h.dbOrderToDTO(updatedOrder))
}

func (h Handlers) GetAuthorization(c echo.Context) error {
	return echo.ErrNotImplemented
}

func (h Handlers) InitiateChallenge(c echo.Context) error {
	payloadBody, err := getPayloadBody(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}
	if string(payloadBody) != "{}" {
		return acme_controller.MalformedProblem("Expected empty JSON object ({}) for payload")
	}

	challID := c.Param(h.LinkCtrl.ChallengeIDParam())
	if challID == "" {
		return acme_controller.MalformedProblem("Empty challenge ID")
	}

	accountID, err := getAccountID(c)
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	err = h.AcmeCtrl.InitiateChallenge([]byte(challID), accountID)
	if err != nil {
		return err
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
	return echo.ErrNotImplemented
}
