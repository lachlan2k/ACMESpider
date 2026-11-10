package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	log "github.com/sirupsen/logrus"
)

const minRSAKeySize = 2048 / 8

var supportedSigningAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256, jose.RS384, jose.RS512}

func checkJWKAlgorithmValidForAccount(alg string, key *jose.JSONWebKey) error {
	switch jose.SignatureAlgorithm(alg) {
	case jose.EdDSA, jose.ES256, jose.ES384, jose.ES512:
		return nil

	case jose.RS256, jose.RS384, jose.RS512:
		if key == nil {
			return nil
		}

		rsaKey, ok := key.Key.(*rsa.PublicKey)
		if !ok {
			return acme_controller.BadPublicKeyProblem(fmt.Sprintf("Algorithm %s requires an RSA key", alg))
		}

		if rsaKey.Size() < minRSAKeySize {
			return acme_controller.BadPublicKeyProblem(fmt.Sprintf("RSA key was too small: %d bits, minimum is %d bits", rsaKey.Size()*8, minRSAKeySize*8))
		}

		return nil

	case "":
		return acme_controller.MalformedProblem("JWS protected header did not contain an algorithm")

	default:
		// Includes "none" and the MAC algorithms, which RFC 8555 6.2 forbids
		return acme_controller.BadSignatureAlgorithmProblem(fmt.Sprintf("Algorithm %q is not supported", alg), supportedSigningAlgorithms)
	}
}

func extractJWS(requestBody []byte) (*jose.JSONWebSignature, *jose.Signature, error) {
	// RFC 8555 6.2
	// "The JWS MUST be in the Flattened JSON Serialization"
	// "The JWS MUST NOT have multiple signatures"
	// "The JWS Unprotected Header [RFC7515] MUST NOT be used"

	// We extract the JWS manually into a struct to:
	// 1) Implicitly ensure it's valid JSON (therefore flattened JSON form, not compact), as json.Unmarshal will fail if its not valid
	// 2) Check for disallowed fields (signatures array, unprotected header)
	// then jose checks the rest

	var disallowedFields struct {
		Header     map[string]string `json:"header"`
		Signatures []interface{}     `json:"signatures"`
	}

	err := json.Unmarshal(requestBody, &disallowedFields)
	if err != nil {
		log.WithError(err).Debug("failed to unmarshal json body")
		return nil, nil, acme_controller.MalformedProblem("Invalid JWS JSON")
	}

	if disallowedFields.Header != nil {
		return nil, nil, acme_controller.MalformedProblem("JWS contained disallowed 'header' field")
	}
	if len(disallowedFields.Signatures) > 0 {
		return nil, nil, acme_controller.MalformedProblem("JWS contained multiple signatures which is not allowed")
	}

	jws, err := jose.ParseSigned(string(requestBody), supportedSigningAlgorithms)
	if err != nil {
		log.WithError(err).Debug("failed to parse jose jws")

		// go-jose enforces the algorithm list itself, so the algorithm check below never sees these
		var unexpectedAlg *jose.ErrUnexpectedSignatureAlgorithm
		if errors.As(err, &unexpectedAlg) {
			if unexpectedAlg.Got == "" {
				return nil, nil, acme_controller.MalformedProblem("JWS protected header did not contain an algorithm")
			}
			// Includes "none" and the MAC algorithms, which RFC 8555 6.2 forbids
			return nil, nil, acme_controller.BadSignatureAlgorithmProblem(fmt.Sprintf("Algorithm %q is not supported", unexpectedAlg.Got), supportedSigningAlgorithms)
		}
		return nil, nil, acme_controller.MalformedProblem("JWS invalid")
	}

	if len(jws.Signatures) != 1 {
		return nil, nil, acme_controller.MalformedProblem("Expected JWS to contain exactly one Signature")
	}

	protected := jws.Signatures[0].Protected
	algCheck := checkJWKAlgorithmValidForAccount(protected.Algorithm, protected.JSONWebKey)
	if algCheck != nil {
		return nil, nil, algCheck
	}

	return jws, &jws.Signatures[0], nil
}

func (h Handlers) lookupKID(kid string) (*jose.JSONWebKey, []byte, error) {
	accountID, err := h.kidToAccountID(kid)
	if err != nil {
		return nil, nil, err
	}

	jwk, err := h.AcmeCtrl.GetAccountKey(accountID)
	if err != nil {
		return nil, nil, err
	}
	return jwk, accountID, err
}

func (h Handlers) kidToAccountID(kid string) ([]byte, error) {
	prefix := h.LinkCtrl.AccountPath("").Abs()
	if !strings.HasPrefix(kid, prefix) {
		return nil, fmt.Errorf("kid %s did not start with %s", kid, prefix)
	}

	id := strings.TrimPrefix(kid, prefix)
	if len(id) == 0 {
		return nil, fmt.Errorf("kid %s did not contain an account Id", kid)
	}
	return []byte(id), nil
}
