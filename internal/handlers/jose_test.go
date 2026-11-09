package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
)

// signedJWS returns a valid ES256 JWS in JSON serialization.
func signedJWS(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}

	return jws.FullSerialize()
}

func TestExtractJWS(t *testing.T) {
	jws := signedJWS(t)

	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{name: "valid", body: []byte(jws)},
		{name: "valid with leading whitespace", body: []byte(" \n\t" + jws)},

		{name: "disallowed header field, invalid type", body: []byte(strings.Replace(jws, "{", `{"header":"z",`, 1)), wantErr: true},
		{name: "disallowed header field, valid type", body: []byte(strings.Replace(jws, "{", `{"header":{"z":"zz"},`, 1)), wantErr: true},
		{name: "disallowed signatures, invalid type", body: []byte(strings.Replace(jws, "{", `{"signatures":{"z":"zz"},`, 1)), wantErr: true},
		{name: "disallowed signatures, valid type", body: []byte(strings.Replace(jws, "{", `{"signatures":[{"z":"zz"}],`, 1)), wantErr: true},

		{name: "nil", body: nil, wantErr: true},
		{name: "empty", body: []byte(""), wantErr: true},
		{name: "empty string", body: []byte(`""`), wantErr: true},
		{name: "string", body: []byte(`"zzz"`), wantErr: true},
		{name: "number", body: []byte(`1`), wantErr: true},
		{name: "empty array", body: []byte("[]"), wantErr: true},
		{name: "array with jws", body: []byte("[" + jws + "]"), wantErr: true},
		{name: "array with multiple jwss", body: []byte("[" + jws + ", " + jws + "]"), wantErr: true},
		{name: "null", body: []byte("null"), wantErr: true},
		{name: "invalid json", body: []byte("{"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := extractJWS(tt.body)
			if (err != nil) != tt.wantErr {
				t.Fatalf("wantErr %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
