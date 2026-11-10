package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v4"
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

// isBase64URL checks s is made only of the base64url alphabet, with no padding, and could be the encoding of
// some octet string. Go's decoder would also accept embedded newlines, which the RFC 7515 profile doesn't.
func isBase64URL(s string) bool {
	if len(s)%4 == 1 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
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
		} else if errors.Is(err, jose.ErrUnsupportedCriticalHeader) {
			// RFC 7515 4.1.11: a JWS with a critical header we don't understand has to be rejected. It's the
			// client's doing, so not a 500 (go-jose v3 reported this as a crypto failure, v4 has its own error).
			return acme_controller.MalformedProblem("JWS marked a header as critical that isn't supported")
		} else {
			return acme_controller.InternalErrorProblem(err)
		}
	}

	// 4. Consume the nonce and check its okay
	// RFC 8555 6.5.2: a nonce that isn't valid base64url (no padding) makes the JWS malformed. A missing or
	// empty nonce is "not present", which is a badNonce below.
	if protected.Nonce != "" && !isBase64URL(protected.Nonce) {
		return acme_controller.MalformedProblem("nonce was not valid base64url")
	}

	nonceOk, nonceErr := h.NonceCtrl.ValidateAndConsume(protected.Nonce)
	if nonceErr != nil {
		log.WithError(nonceErr).Debug("failed to validate nonce")
	}
	if !nonceOk || nonceErr != nil {
		// RFC 8555 6.5: a missing, unknown, expired or reused nonce is a badNonce, and the response
		// carries a fresh nonce to retry with
		return acme_controller.BadNonceProblem("nonce was invalid")
	}

	// 5. Ensure the URL in the protected headers matches the URL requested
	protURL := protected.ExtraHeaders["url"]
	protURLStr, protURLOk := protURL.(string)
	if !protURLOk {
		return acme_controller.MalformedProblem("JWS header did not contain a URL")
	}
	if !h.LinkCtrl.CompareURL(c.Request().RequestURI, protURLStr) {
		// RFC 8555 6.4: a url that doesn't match the request must be rejected as unauthorized
		return acme_controller.UnauthorizedProblem(fmt.Sprintf("URL in JWS header did not match URL requested (%s vs %s)", c.Request().URL.String(), protURLStr))
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
