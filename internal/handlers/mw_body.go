package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v3"
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	log "github.com/sirupsen/logrus"
)

const payloadBodyCtxKey = "payloadBody"
const protectedHeaderCtxKey = "protectedHeader"
const accountIDCtxKey = "accountID"

// body, internalErr, userErr
func getPayloadBoundBody[BodyT any](c echo.Context) (*BodyT, error) {
	data := c.Get(payloadBodyCtxKey)
	if data == nil {
		return nil, acme_controller.InternalErrorProblem(fmt.Errorf("%s on context was nil", payloadBodyCtxKey))
	}
	dataBuff, ok := data.([]byte)
	if !ok {
		return nil, acme_controller.InternalErrorProblem(fmt.Errorf("%s on context couldn't be cast to []byte", payloadBodyCtxKey))
	}

	var decodedBody BodyT
	err := json.Unmarshal(dataBuff, &decodedBody)
	if err != nil {
		return nil, acme_controller.MalformedProblem("Invalid JSON")
	}

	return &decodedBody, nil
}

func getPayloadBody(c echo.Context) ([]byte, error) {
	data := c.Get(payloadBodyCtxKey)
	if data == nil {
		return nil, errors.New("payloadBody on context was nil")
	}
	dataBuff, ok := data.([]byte)
	if !ok {
		return nil, errors.New("payloadBody couldn't be cast to []byte")
	}

	return dataBuff, nil
}

// POST-as-GET requests should contain an empty string for payload
// and some endpoints want "{}"
func ensurePayloadIs(c echo.Context, expected string) (bool, error) {
	dataBuff, err := getPayloadBody(c)
	if err != nil {
		return false, err
	}

	return string(dataBuff) == expected, nil
}

func getProtectedHeader(c echo.Context) (*jose.Header, error) {
	data := c.Get(protectedHeaderCtxKey)
	if data == nil {
		return nil, errors.New("protectedHeader on context was nil")
	}
	out, ok := data.(*jose.Header)
	if !ok {
		return nil, errors.New("protectedHeader couldn't be cast to dto")
	}
	return out, nil
}

func getAccountID(c echo.Context) ([]byte, error) {
	data := c.Get(accountIDCtxKey)
	if data == nil {
		return nil, errors.New("accountID on context was nil")
	}
	out, ok := data.([]byte)
	if !ok {
		return nil, errors.New("accountID on context couldn't be cast to []byte")
	}
	return out, nil
}

func (h Handlers) validateJWSAndExtractPayload(next echo.HandlerFunc, c echo.Context, allowKID bool, allowJWK bool) error {
	if c.Request().Header.Get("Content-Type") != "application/jose+json" {
		return acme_controller.UnsupportedMediaTypeProblem("")
	}

	requestBody, err := io.ReadAll(c.Request().Body)

	if err != nil {
		log.WithError(err).Debug("failed to read request body")
		return acme_controller.MalformedProblem("Request body could not be read")
	}

	jws, sig, err := extractJWS(requestBody)
	if err != nil {
		return err
	}

	protected := sig.Protected

	kidProvided := protected.KeyID != ""
	jwkProvided := protected.JSONWebKey != nil

	if kidProvided && jwkProvided {
		return acme_controller.MalformedProblem("JWS contained both a KID and JWK - these are mutually exclusive")
	}
	if !kidProvided && !jwkProvided {
		return acme_controller.MalformedProblem("JWS did not provide a KID or a JWK")
	}
	if kidProvided && !allowKID {
		return acme_controller.MalformedProblem("JWS provided a KID, but this endpoint does not allow KIDs")
	}
	if jwkProvided && !allowJWK {
		return acme_controller.MalformedProblem("JWS provided a JWK, but this endpoint does not allow JWKs")
	}

	// If a JWK is provided (and allowed), then we use that to self-validate the signature
	// This is only really used when first creating an account
	// Otherwise, we use the KID to grab the JWS they registered with and use that to validate the signature

	var accountID []byte
	jwk := protected.JSONWebKey
	if jwk == nil {
		jwk, accountID, err = h.lookupKID(protected.KeyID)
		if jwk == nil || err != nil {
			log.WithError(err).WithField("kid", protected.KeyID).Debug("KID lookup is not tied to a valid key")
			return acme_controller.UnauthorizedProblem("")
		}
	}

	payload, err := jws.Verify(jwk)
	if err != nil {
		if errors.Is(err, jose.ErrCryptoFailure) {
			return acme_controller.UnauthorizedProblem("Invalid JWS signature")
		} else {
			return acme_controller.InternalErrorProblem(err)
		}
	}

	// 4. Consume the nonce and check its okay
	nonceOk, nonceErr := h.NonceCtrl.ValidateAndConsume(protected.Nonce)
	if nonceErr != nil {
		log.WithError(err).Debugf("failed to validate nonce: %v", nonceErr)
	}
	if !nonceOk || nonceErr != nil {
		return acme_controller.MalformedProblem("nonce was invalid")
	}

	// 5. Ensure the URL in the protected headers matches the URL requested
	protURL := protected.ExtraHeaders["url"]
	protURLStr, protURLOk := protURL.(string)
	if !protURLOk {
		return acme_controller.MalformedProblem("JWS header did not contain a URL")
	}
	if !h.LinkCtrl.CompareURL(c.Request().RequestURI, protURLStr) {
		return acme_controller.MalformedProblem(fmt.Sprintf("URL in JWS header did not match URL requested (%s vs %s)", c.Request().URL.String(), protURLStr))
	}

	c.Set(payloadBodyCtxKey, payload)
	c.Set(protectedHeaderCtxKey, &protected)
	c.Set(accountIDCtxKey, accountID)

	return next(c)
}

func (h Handlers) ValidateJWSWithKIDAndExtractPayload(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return h.validateJWSAndExtractPayload(next, c, true, false)
	}
}

func (h Handlers) ValidateJWSWithJWKAndExtractPayload(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return h.validateJWSAndExtractPayload(next, c, false, true)
	}
}

func (h Handlers) ValidateJWSWithKIDOrJWKAndExtractPayload(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return h.validateJWSAndExtractPayload(next, c, true, true)
	}
}

func (h Handlers) POSTAsGETMw(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		valid, err := ensurePayloadIs(c, "")
		if !valid {
			return acme_controller.MalformedProblem("Invalid POST-as-GET request: expected signed request with empty string as payload")
		}
		if err != nil {
			return acme_controller.InternalErrorProblem(fmt.Errorf("failed to check payload body was empty: %v", err))
		}

		return next(c)
	}
}
