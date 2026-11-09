package handlers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/links"
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

// joseMalformedType is the ACME problem type extractJWS should use for every rejection.
const joseMalformedType = "urn:ietf:params:acme:error:malformed"

const (
	joseBadSigAlgType    = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	joseBadPublicKeyType = "urn:ietf:params:acme:error:badPublicKey"
)

func requireProblem(t *testing.T, err error, wantType string) *acme_controller.ProblemDetails {
	t.Helper()

	var pd *acme_controller.ProblemDetails
	if !errors.As(err, &pd) {
		t.Fatalf("expected a ProblemDetails, got %T: %v", err, err)
	}
	if pd.Type != wantType || pd.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("got (%s, %d: %q), want (%s, %d)", pd.Type, pd.HTTPStatus, pd.Detail, wantType, http.StatusBadRequest)
	}
	return pd
}

func requireMalformed(t *testing.T, err error) {
	t.Helper()
	requireProblem(t, err, joseMalformedType)
}

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// jwsWithHeader builds a flattened JWS around an arbitrary protected header. The signature is only a
// placeholder, which is enough for anything that is rejected before verification.
func jwsWithHeader(header string) string {
	return `{"protected":"` + b64url(header) + `","payload":"","signature":"AAAA"}`
}

// signES256 hand-signs a JWS with exactly the given protected header, bypassing go-jose's signer
// so headers it would refuse to produce can be used.
func signES256(t *testing.T, key *ecdsa.PrivateKey, header string, payload string) string {
	t.Helper()

	protected, encodedPayload := b64url(header), b64url(payload)
	digest := sha256.Sum256([]byte(protected + "." + encodedPayload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return `{"protected":"` + protected + `","payload":"` + encodedPayload + `","signature":"` + base64.RawURLEncoding.EncodeToString(sig) + `"}`
}

func signWithAlg(t *testing.T, alg jose.SignatureAlgorithm, key any, embedJWK bool) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, &jose.SignerOptions{EmbedJWK: embedJWK})
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	return jws.FullSerialize()
}

func TestExtractJWSReturnsParsedValues(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := signWithAlg(t, jose.ES256, key, true)

	jws, sig, err := extractJWS([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(jws.Signatures) != 1 || sig != &jws.Signatures[0] {
		t.Fatal("returned signature should point at the JWS's only signature")
	}
	if sig.Protected.Algorithm != "ES256" || sig.Protected.JSONWebKey == nil {
		t.Errorf("unexpected protected header: %+v", sig.Protected)
	}

	payload, err := jws.Verify(key.Public())
	if err != nil || string(payload) != "payload" {
		t.Errorf("payload = %q, err %v", payload, err)
	}
}

func TestExtractJWSAlgorithms(t *testing.T) {
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ec521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsa1536, _ := rsa.GenerateKey(rand.Reader, 1536)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	hmacKey := []byte(strings.Repeat("k", 64))

	tests := []struct {
		name     string
		alg      jose.SignatureAlgorithm
		key      any
		embedJWK bool
		wantType string // empty means accepted
	}{
		{"ES256", jose.ES256, ec256, true, ""},
		{"ES384", jose.ES384, ec384, true, ""},
		{"ES512", jose.ES512, ec521, true, ""},
		{"EdDSA", jose.EdDSA, ed, true, ""},
		{"RS256 2048", jose.RS256, rsa2048, true, ""},
		{"RS384 2048", jose.RS384, rsa2048, true, ""},
		{"RS512 2048", jose.RS512, rsa2048, true, ""},
		{"RS256 3072", jose.RS256, rsa3072, true, ""},

		{"RS256 1024 embedded", jose.RS256, rsa1024, true, joseBadPublicKeyType},
		{"RS256 1536 embedded", jose.RS256, rsa1536, true, joseBadPublicKeyType},
		{"RS512 1024 embedded", jose.RS512, rsa1024, true, joseBadPublicKeyType},
		// With a KID there's no embedded key to size-check here; the key was checked when the account was created
		{"RS256 1024 by kid", jose.RS256, rsa1024, false, ""},

		{"HS256", jose.HS256, hmacKey, false, joseBadSigAlgType},
		{"HS384", jose.HS384, hmacKey, false, joseBadSigAlgType},
		{"HS512", jose.HS512, hmacKey, false, joseBadSigAlgType},
		{"PS256", jose.PS256, rsa2048, true, joseBadSigAlgType},
		{"PS384", jose.PS384, rsa2048, true, joseBadSigAlgType},
		{"PS512", jose.PS512, rsa2048, true, joseBadSigAlgType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := extractJWS([]byte(signWithAlg(t, tt.alg, tt.key, tt.embedJWK)))
			if tt.wantType == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			requireProblem(t, err, tt.wantType)
		})
	}
}

// RFC 8555 6.2: the problem must list the algorithms the server does support
func TestBadSignatureAlgorithmListsSupportedAlgorithms(t *testing.T) {
	_, _, err := extractJWS([]byte(jwsWithHeader(`{"alg":"HS256"}`)))
	pd := requireProblem(t, err, joseBadSigAlgType)

	for _, want := range []string{"ES256", "EdDSA"} {
		found := false
		for _, got := range pd.Algorithms {
			found = found || got == want
		}
		if !found {
			t.Errorf("algorithms %v should include %s", pd.Algorithms, want)
		}
	}
	for _, got := range pd.Algorithms {
		if strings.HasPrefix(got, "HS") || got == "none" {
			t.Errorf("algorithms must not advertise %s", got)
		}
	}

	body, _ := json.Marshal(pd)
	if !strings.Contains(string(body), `"algorithms":["ES256"`) {
		t.Errorf("algorithms missing from the serialised problem: %s", body)
	}

	// Other problems must not grow an empty algorithms field
	_, _, err = extractJWS([]byte("{"))
	body, _ = json.Marshal(requireProblem(t, err, joseMalformedType))
	if strings.Contains(string(body), "algorithms") {
		t.Errorf("unexpected algorithms field: %s", body)
	}
}

func TestExtractJWSRejectsBadProtectedHeaders(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"alg none", `{"alg":"none"}`},
		{"alg None", `{"alg":"None"}`},
		{"alg missing", `{"kid":"x"}`},
		{"alg empty", `{"alg":""}`},
		{"alg null", `{"alg":null}`},
		{"alg number", `{"alg":256}`},
		{"alg unknown", `{"alg":"ES999"}`},
		{"alg lower case", `{"alg":"es256"}`},
		{"alg trailing space", `{"alg":"ES256 "}`},
		{"alg HS256", `{"alg":"HS256"}`},
		{"alg RSA-OAEP", `{"alg":"RSA-OAEP"}`},
		{"alg dir", `{"alg":"dir"}`},

		{"jwk is a string", `{"alg":"ES256","jwk":"x"}`},
		{"jwk is an empty object", `{"alg":"ES256","jwk":{}}`},
		{"jwk unknown kty", `{"alg":"ES256","jwk":{"kty":"foo"}}`},
		{"jwk symmetric", `{"alg":"ES256","jwk":{"kty":"oct","k":"AAAA"}}`},
		{"jwk EC with missing coordinates", `{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256"}}`},
		{"jwk EC with unknown curve", `{"alg":"ES256","jwk":{"kty":"EC","crv":"P-999","x":"AAAA","y":"AAAA"}}`},
		{"jwk EC point not on curve", `{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}}`},

		{"kid is a number", `{"alg":"ES256","kid":5}`},
		{"kid is an object", `{"alg":"ES256","kid":{}}`},
		{"nonce is a number", `{"alg":"ES256","nonce":5}`},
	}
	// A usable but unsupported algorithm is badSignatureAlgorithm; a missing or unparseable one is just malformed
	unsupportedAlg := map[string]bool{
		"alg none": true, "alg None": true, "alg unknown": true, "alg lower case": true,
		"alg trailing space": true, "alg HS256": true, "alg RSA-OAEP": true, "alg dir": true,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := extractJWS([]byte(jwsWithHeader(tt.header)))
			if unsupportedAlg[tt.name] {
				requireProblem(t, err, joseBadSigAlgType)
				return
			}
			requireMalformed(t, err)
		})
	}
}

func TestExtractJWSRejectsBadEnvelopes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	valid := signWithAlg(t, jose.ES256, key, true)

	tests := []struct {
		name string
		body string
	}{
		{"byte order mark", "\xef\xbb\xbf" + valid},
		{"trailing garbage", valid + "x"},
		{"two objects", valid + valid},
		{"unterminated", valid[:len(valid)-1]},
		{"missing payload", `{"protected":"` + b64url(`{"alg":"ES256"}`) + `","signature":"AAAA"}`},
		{"payload is a number", `{"protected":"` + b64url(`{"alg":"ES256"}`) + `","payload":1,"signature":"AAAA"}`},
		{"protected is an object", `{"protected":{"alg":"ES256"},"payload":"","signature":"AAAA"}`},
		{"signature is an object", `{"protected":"` + b64url(`{"alg":"ES256"}`) + `","payload":"","signature":{}}`},
		{"standard base64 alphabet", `{"protected":"` + b64url(`{"alg":"ES256"}`) + `","payload":"+/+/","signature":"AAAA"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := extractJWS([]byte(tt.body))
			requireMalformed(t, err)
		})
	}
}

// validateJWSAndExtractPayload relies on jws.Verify returning ErrCryptoFailure for anything an attacker can
// do to a signature or key; any other error is turned into a 500. Pin that go-jose behaves that way.
func TestVerifyFailuresAreCryptoFailures(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherEC, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)

	es256 := signWithAlg(t, jose.ES256, ec, false)
	sigStart := strings.Index(es256, `"signature":"`) + len(`"signature":"`)
	withSignature := func(sig string) string { return es256[:sigStart] + sig + `"}` }

	tests := []struct {
		name string
		body string
		key  any
	}{
		{"different key of same type", es256, otherEC.Public()},
		{"ES256 signature, P-384 key", es256, p384.Public()},
		{"ES256 signature, RSA key", es256, &rsaKey.PublicKey},
		{"ES256 signature, Ed25519 key", es256, ed.Public()},
		{"RS256 signature, EC key", signWithAlg(t, jose.RS256, rsaKey, false), ec.Public()},
		{"EdDSA signature, EC key", signWithAlg(t, jose.EdDSA, ed, false), ec.Public()},
		{"symmetric key", es256, jose.JSONWebKey{Key: []byte("secret")}},
		{"empty signature", withSignature(""), ec.Public()},
		{"short signature", withSignature("AAAA"), ec.Public()},
		{"all zero signature", withSignature(strings.Repeat("A", 86)), ec.Public()},
		{"overlong signature", withSignature(strings.Repeat("A", 400)), ec.Public()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jws, err := jose.ParseSigned(tt.body)
			if err != nil {
				t.Fatalf("test input should parse: %v", err)
			}
			_, err = jws.Verify(tt.key)
			if !errors.Is(err, jose.ErrCryptoFailure) {
				t.Fatalf("got %v, want ErrCryptoFailure (anything else becomes a 500)", err)
			}
		})
	}
}

// RFC 7515 4.1.11: a JWS with a critical extension the recipient doesn't understand must be rejected.
func TestVerifyRejectsUnknownCriticalHeaders(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{"no crit", `{"alg":"ES256"}`, false},
		{"unknown extension", `{"alg":"ES256","crit":["exp"],"exp":1}`, true},
		{"unknown extension not present in header", `{"alg":"ES256","crit":["x-foo"]}`, true},
		{"crit lists a registered parameter", `{"alg":"ES256","crit":["alg"]}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := signES256(t, key, tt.header, "")
			jws, err := jose.ParseSigned(body)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("unexpected parse error: %v", err)
				}
				return
			}
			_, err = jws.Verify(key.Public())
			if (err != nil) != tt.wantErr {
				t.Fatalf("wantErr %v, got %v", tt.wantErr, err)
			}
			if err != nil && !errors.Is(err, jose.ErrCryptoFailure) {
				t.Errorf("rejection should be an ErrCryptoFailure so it maps to 403 rather than 500, got %v", err)
			}
		})
	}
}

func TestExtractJWSAcceptsEmptyAndNonEmptyPayloads(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	for name, payload := range map[string]string{"empty (POST-as-GET)": "", "object": "{}", "text": "hello", "large": strings.Repeat("a", 1<<20)} {
		t.Run(name, func(t *testing.T) {
			body := signES256(t, key, `{"alg":"ES256","kid":"https://example.com/acme/account/x"}`, payload)
			jws, sig, err := extractJWS([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if sig.Protected.KeyID != "https://example.com/acme/account/x" {
				t.Errorf("kid = %q", sig.Protected.KeyID)
			}
			got, err := jws.Verify(key.Public())
			if err != nil || string(got) != payload {
				t.Errorf("verify: len(payload)=%d err=%v", len(got), err)
			}
		})
	}
}

func TestKidToAccountID(t *testing.T) {
	h := Handlers{LinkCtrl: links.LinkController{BaseURL: "https://example.com/acme"}}

	tests := []struct {
		kid     string
		want    string
		wantErr bool
	}{
		{"https://example.com/acme/account/abc123", "abc123", false},
		{"https://example.com/acme/account/", "", true},
		{"https://example.com/acme/account", "", true},
		{"", "", true},
		{"abc123", "", true},
		{"http://example.com/acme/account/abc123", "", true},
		{"https://evil.example.org/acme/account/abc123", "", true},
		{"https://example.com/acme/order/abc123", "", true},
		{"https://example.com/acme/account/abc/orders", "abc/orders", false}, // lookup will simply fail
	}
	for _, tt := range tests {
		t.Run(tt.kid, func(t *testing.T) {
			got, err := h.kidToAccountID(tt.kid)
			if (err != nil) != tt.wantErr || string(got) != tt.want {
				t.Fatalf("got (%q, %v), want (%q, wantErr=%v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}
