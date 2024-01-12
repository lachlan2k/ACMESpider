package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	log "github.com/sirupsen/logrus"
)

const minRSAKeySize = 2048 / 8

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
			return fmt.Errorf("couldn't check RSA key")
		}

		if rsaKey.Size() < minRSAKeySize {
			return fmt.Errorf("rsa key was too small: %d bits, minimum is %d bits", rsaKey.Size()*8, minRSAKeySize*8)
		}

		return nil

	default:
		return fmt.Errorf("algorithm %s is not supported", alg)
	}
}

func extractJWS(requestBody []byte) (*jose.JSONWebSignature, *jose.Signature, error) {
	if len(requestBody) == 0 || requestBody[0] != '{' {
		return nil, nil, acme_controller.MalformedProblem("Invalid JSON")
	}

	// we extract into here to ensure there are no dis-allowed fields
	// before we parse with jose
	var disallowedFields struct {
		Header     map[string]string `json:"header"`
		Signatures []interface{}     `json:"signatures"`
	}

	err := json.Unmarshal(requestBody, &disallowedFields)
	if err != nil {
		log.WithError(err).Debug("failed to unmarshal json body")
		return nil, nil, acme_controller.MalformedProblem("Invalid JSON")
	}

	if disallowedFields.Header != nil {
		return nil, nil, acme_controller.MalformedProblem("JWS contained disallowed 'header' field")
	}
	if len(disallowedFields.Signatures) > 0 {
		return nil, nil, acme_controller.MalformedProblem("JWS contained multiple signatures which is not allowed")
	}

	jws, err := jose.ParseSigned(string(requestBody))
	if err != nil {
		log.WithError(err).Debug("failed to parse jose jws")
		return nil, nil, acme_controller.MalformedProblem("JWS invalid")
	}

	if len(jws.Signatures) != 1 {
		return nil, nil, acme_controller.MalformedProblem("Expected JWS to contain exactly one Signature")
	}

	protected := jws.Signatures[0].Protected
	algCheck := checkJWKAlgorithmValidForAccount(protected.Algorithm, protected.JSONWebKey)
	if algCheck != nil {
		return nil, nil, acme_controller.MalformedProblem(fmt.Sprintf("Supplied JWS algorithm of %s is not valid: %s", protected.Algorithm, algCheck.Error()))
	}

	return jws, &jws.Signatures[0], nil
}

func (h Handlers) lookupKID(kid string) (*jose.JSONWebKey, []byte, error) {
	accountID, err := h.kidToAccountID(kid)
	if err != nil {
		return nil, nil, err
	}

	jwk, err := h.DB.GetAccountKey(accountID)
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
