package dtos

import (
	"github.com/go-jose/go-jose/v3"
)

type WrappedBodyDTO struct {
	ProtectedB64 string `json:"protected"`
	PayloadB64   string `json:"payload"`
	Signature    string `json:"signature"`
}

type ProtectedBodyDTO struct {
	Algorithm string           `json:"alg"`
	JWK       *jose.JSONWebKey `json:"jwk"`
	KID       *string          `json:"kid"`
	Nonce     string           `json:"nonce"`
	URL       string           `json:"url"`
}
