package handlers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/links"
	"github.com/lachlan2k/acmespider/internal/nonce"
)

const (
	errMalformed    = "urn:ietf:params:acme:error:malformed"
	errUnauthorized = "urn:ietf:params:acme:error:unauthorized"
	errUnsupported  = errMalformed // unsupported media type reuses malformed type
	reqURI          = "/acme/new-account"
)

type joseEnv struct {
	h       Handlers
	db      db.DB
	accKey  *ecdsa.PrivateKey
	accKID  string
	baseURL string
}

func newJoseEnv(t *testing.T) *joseEnv {
	t.Helper()

	d, err := db.NewBoltDb(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Seed(); err != nil {
		t.Fatal(err)
	}

	lc := links.LinkController{BaseURL: "https://example.com/acme"}
	h := Handlers{
		AcmeCtrl:  acme_controller.New(d, nil, lc),
		NonceCtrl: nonce.NewInMemCtrl(),
		LinkCtrl:  lc,
	}

	accKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := h.AcmeCtrl.NewAccount(dtos.AccountRequestDTO{}, jose.JSONWebKey{Key: accKey.Public()})
	if err != nil {
		t.Fatal(err)
	}

	return &joseEnv{h: h, db: d, accKey: accKey, accKID: lc.AccountPath(acc.ID).Abs(), baseURL: lc.BaseURL}
}

func (e *joseEnv) nonce(t *testing.T) string {
	t.Helper()
	n, err := e.h.NonceCtrl.Gen()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// jwsSpec describes a request to sign; unset optional fields are omitted from the protected header.
type jwsSpec struct {
	key      any
	alg      jose.SignatureAlgorithm
	embedJWK bool
	kid      string
	nonce    *string
	url      *string
	payload  string
}

func sp(s string) *string { return &s }

func (e *joseEnv) validSpec(t *testing.T) jwsSpec {
	return jwsSpec{
		key:   e.accKey,
		alg:   jose.ES256,
		kid:   e.accKID,
		nonce: sp(e.nonce(t)),
		url:   sp(e.baseURL + "/new-account"),
	}
}

func (s jwsSpec) sign(t *testing.T) string {
	t.Helper()

	opts := &jose.SignerOptions{EmbedJWK: s.embedJWK}
	if s.nonce != nil {
		opts.WithHeader("nonce", *s.nonce)
	}
	if s.url != nil {
		opts.WithHeader("url", *s.url)
	}

	var key any = s.key
	if s.kid != "" {
		key = jose.JSONWebKey{Key: s.key, KeyID: s.kid}
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte(s.payload))
	if err != nil {
		t.Fatal(err)
	}
	return jws.FullSerialize()
}

type mwResult struct {
	err        error
	nextCalled bool
	ctx        echo.Context
}

func (e *joseEnv) run(contentType string, body string, allowKID, allowJWK bool) mwResult {
	req := httptest.NewRequest(http.MethodPost, reqURI, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c := echo.New().NewContext(req, httptest.NewRecorder())

	var res mwResult
	res.ctx = c
	res.err = e.h.validateJWSAndExtractPayload(func(echo.Context) error {
		res.nextCalled = true
		return nil
	}, c, allowKID, allowJWK)
	return res
}

func (e *joseEnv) runJWS(body string, allowKID, allowJWK bool) mwResult {
	return e.run("application/jose+json", body, allowKID, allowJWK)
}

func expectProblem(t *testing.T, res mwResult, wantType string, wantStatus int) {
	t.Helper()

	if res.nextCalled {
		t.Fatal("next handler must not be called on failure")
	}
	var pd *acme_controller.ProblemDetails
	if !errors.As(res.err, &pd) {
		t.Fatalf("expected ProblemDetails, got %T: %v", res.err, res.err)
	}
	if pd.Type != wantType || pd.HTTPStatus != wantStatus {
		t.Fatalf("got (%s, %d: %q), want (%s, %d)", pd.Type, pd.HTTPStatus, pd.Detail, wantType, wantStatus)
	}
}

// RFC 8555 6.5: a missing, unknown, expired or reused nonce is a badNonce (400)
func expectBadNonce(t *testing.T, res mwResult) {
	t.Helper()
	expectProblem(t, res, "urn:ietf:params:acme:error:badNonce", http.StatusBadRequest)
}

func expectMalformed(t *testing.T, res mwResult) {
	t.Helper()
	expectProblem(t, res, errMalformed, http.StatusBadRequest)
}

func TestValidateJWS_Success(t *testing.T) {
	t.Run("kid", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.payload = `{"hello":"world"}`

		res := e.runJWS(s.sign(t), true, false)
		if res.err != nil || !res.nextCalled {
			t.Fatalf("err=%v nextCalled=%v", res.err, res.nextCalled)
		}

		payload, err := getPayloadBody(res.ctx)
		if err != nil || string(payload) != s.payload {
			t.Errorf("payload = %q, err %v", payload, err)
		}
		hdr, err := getProtectedHeader(res.ctx)
		if err != nil || hdr.KeyID != e.accKID {
			t.Errorf("protected header = %+v, err %v", hdr, err)
		}
		id, err := getAccountID(res.ctx)
		if err != nil || string(id) != strings.TrimPrefix(e.accKID, e.h.LinkCtrl.AccountPath("").Abs()) {
			t.Errorf("accountID = %q, err %v", id, err)
		}
	})

	t.Run("jwk", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.kid, s.embedJWK = "", true

		res := e.runJWS(s.sign(t), false, true)
		if res.err != nil || !res.nextCalled {
			t.Fatalf("err=%v nextCalled=%v", res.err, res.nextCalled)
		}
		if id, _ := getAccountID(res.ctx); id != nil {
			t.Errorf("JWK requests have no account yet, got %q", id)
		}
	})

	t.Run("either allowed", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		if res := e.runJWS(s.sign(t), true, true); res.err != nil {
			t.Fatal(res.err)
		}
		s = e.validSpec(t)
		s.kid, s.embedJWK = "", true
		if res := e.runJWS(s.sign(t), true, true); res.err != nil {
			t.Fatal(res.err)
		}
	})

	t.Run("post-as-get empty payload", func(t *testing.T) {
		e := newJoseEnv(t)
		res := e.runJWS(e.validSpec(t).sign(t), true, false)
		if res.err != nil {
			t.Fatal(res.err)
		}
		if ok, err := ensurePayloadIs(res.ctx, ""); !ok || err != nil {
			t.Errorf("ensurePayloadIs = %v, %v", ok, err)
		}
	})

	t.Run("supported algorithms", func(t *testing.T) {
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, edKey, _ := ed25519.GenerateKey(rand.Reader)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

		tests := []struct {
			alg jose.SignatureAlgorithm
			key any
		}{
			{jose.RS256, rsaKey}, {jose.RS384, rsaKey}, {jose.RS512, rsaKey},
			{jose.ES384, p384}, {jose.ES512, p521}, {jose.EdDSA, edKey},
		}
		for _, tt := range tests {
			t.Run(string(tt.alg), func(t *testing.T) {
				e := newJoseEnv(t)
				s := e.validSpec(t)
				s.kid, s.embedJWK, s.alg, s.key = "", true, tt.alg, tt.key
				if res := e.runJWS(s.sign(t), false, true); res.err != nil {
					t.Fatal(res.err)
				}
			})
		}
	})
}

func TestValidateJWS_ContentType(t *testing.T) {
	e := newJoseEnv(t)
	body := e.validSpec(t).sign(t)

	for _, ct := range []string{"", "application/json", "application/jose", "application/jose+json; charset=utf-8", "APPLICATION/JOSE+JSON", "text/plain"} {
		t.Run("content-type "+ct, func(t *testing.T) {
			expectProblem(t, e.run(ct, body, true, true), errUnsupported, http.StatusUnsupportedMediaType)
		})
	}
}

func TestValidateJWS_KeyIdentification(t *testing.T) {
	t.Run("both kid and jwk", func(t *testing.T) {
		// go-jose puts the key ID inside the embedded JWK rather than the protected header,
		// so hand-sign a JWS that has both "kid" and "jwk" at the top level of the header.
		e := newJoseEnv(t)
		jwkJSON, err := jose.JSONWebKey{Key: e.accKey.Public()}.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		hdr := `{"alg":"ES256","kid":"` + e.accKID + `","jwk":` + string(jwkJSON) +
			`,"nonce":"` + e.nonce(t) + `","url":"` + e.baseURL + `/new-account"}`
		protected := base64.RawURLEncoding.EncodeToString([]byte(hdr))
		payload := ""

		digest := sha256.Sum256([]byte(protected + "." + payload))
		r, sv, err := ecdsa.Sign(rand.Reader, e.accKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		sv.FillBytes(sig[32:])

		body := `{"protected":"` + protected + `","payload":"` + payload + `","signature":"` +
			base64.RawURLEncoding.EncodeToString(sig) + `"}`

		// Sanity check: the same JWS is otherwise valid, so the rejection is down to the kid/jwk exclusivity.
		if _, _, err := extractJWS([]byte(body)); err != nil {
			t.Fatalf("hand-signed JWS should parse: %v", err)
		}
		expectMalformed(t, e.runJWS(body, true, true))
	})

	t.Run("neither kid nor jwk", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.kid = ""
		expectMalformed(t, e.runJWS(s.sign(t), true, true))
	})

	t.Run("kid on jwk-only endpoint", func(t *testing.T) {
		e := newJoseEnv(t)
		expectMalformed(t, e.runJWS(e.validSpec(t).sign(t), false, true))
	})

	t.Run("jwk on kid-only endpoint", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.kid, s.embedJWK = "", true
		expectMalformed(t, e.runJWS(s.sign(t), true, false))
	})

	t.Run("failed kind check doesn't consume nonce", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		_ = e.runJWS(s.sign(t), false, true) // rejected: kid on jwk-only
		if res := e.runJWS(s.sign(t), true, false); res.err != nil {
			t.Fatalf("nonce should still be valid: %v", res.err)
		}
	})

	kidTests := []struct {
		name string
		kid  func(e *joseEnv) string
	}{
		{"unknown account", func(e *joseEnv) string { return e.h.LinkCtrl.AccountPath("doesnotexist").Abs() }},
		{"kid without account id", func(e *joseEnv) string { return e.h.LinkCtrl.AccountPath("").Abs() }},
		{"kid is bare id", func(e *joseEnv) string { return strings.TrimPrefix(e.accKID, e.h.LinkCtrl.AccountPath("").Abs()) }},
		{"kid on another host", func(e *joseEnv) string {
			return strings.Replace(e.accKID, "example.com", "evil.example.org", 1)
		}},
		{"kid with trailing path", func(e *joseEnv) string { return e.accKID + "/orders" }},
		{"kid with different case prefix", func(e *joseEnv) string { return strings.ToUpper(e.accKID) }},
	}
	for _, tt := range kidTests {
		t.Run(tt.name, func(t *testing.T) {
			e := newJoseEnv(t)
			s := e.validSpec(t)
			s.kid = tt.kid(e)
			expectProblem(t, e.runJWS(s.sign(t), true, false), errUnauthorized, http.StatusForbidden)
		})
	}

	t.Run("deleted account", func(t *testing.T) {
		e := newJoseEnv(t)
		id := strings.TrimPrefix(e.accKID, e.h.LinkCtrl.AccountPath("").Abs())
		if _, err := e.h.AcmeCtrl.UpdateAccount([]byte(id), []byte(id), dtos.AccountRequestDTO{Status: dtos.AccountStatusDeactivated}); err != nil {
			t.Fatal(err)
		}
		res := e.runJWS(e.validSpec(t).sign(t), true, false)
		expectProblem(t, res, errUnauthorized, http.StatusForbidden)
	})
}

func TestValidateJWS_Signature(t *testing.T) {
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("kid signed by wrong key", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.key = otherKey
		expectProblem(t, e.runJWS(s.sign(t), true, false), errUnauthorized, http.StatusForbidden)
	})

	t.Run("tampered signature", func(t *testing.T) {
		e := newJoseEnv(t)
		body := e.validSpec(t).sign(t)
		i := strings.Index(body, `"signature":"`) + len(`"signature":"`)
		flipped := "A"
		if body[i] == 'A' {
			flipped = "B"
		}
		expectProblem(t, e.runJWS(body[:i]+flipped+body[i+1:], true, false), errUnauthorized, http.StatusForbidden)
	})

	t.Run("tampered payload", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.payload = `{"a":1}`
		body := s.sign(t)
		evil := base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))
		good := base64.RawURLEncoding.EncodeToString([]byte(s.payload))
		expectProblem(t, e.runJWS(strings.Replace(body, good, evil, 1), true, false), errUnauthorized, http.StatusForbidden)
	})

	t.Run("tampered protected header", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		body := s.sign(t)
		evilURL := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"` + e.accKID + `","nonce":"` + *s.nonce + `","url":"https://example.com/acme/revoke-cert"}`))
		i := strings.Index(body, `"protected":"`) + len(`"protected":"`)
		j := i + strings.Index(body[i:], `"`)
		expectProblem(t, e.runJWS(body[:i]+evilURL+body[j:], true, false), errUnauthorized, http.StatusForbidden)
	})

	t.Run("jwk embedded but signed by different key", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.kid, s.embedJWK = "", true
		body := s.sign(t)

		// swap in someone else's public key in the embedded jwk
		other, _ := jose.JSONWebKey{Key: otherKey.Public()}.MarshalJSON()
		self, _ := jose.JSONWebKey{Key: e.accKey.Public()}.MarshalJSON()
		_ = self
		hdrB64 := body[strings.Index(body, `"protected":"`)+len(`"protected":"`):]
		hdrB64 = hdrB64[:strings.Index(hdrB64, `"`)]
		raw, _ := base64.RawURLEncoding.DecodeString(hdrB64)
		start := strings.Index(string(raw), `"jwk":`) + len(`"jwk":`)
		end := start + strings.Index(string(raw)[start:], "}") + 1
		newHdr := string(raw)[:start] + string(other) + string(raw)[end:]
		forged := strings.Replace(body, hdrB64, base64.RawURLEncoding.EncodeToString([]byte(newHdr)), 1)

		expectProblem(t, e.runJWS(forged, false, true), errUnauthorized, http.StatusForbidden)
	})

	t.Run("algorithm does not match key type", func(t *testing.T) {
		// Header claims RS256 but the registered key is ECDSA: must not be accepted, and must not be a 500.
		e := newJoseEnv(t)
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		s := e.validSpec(t)
		s.alg, s.key = jose.RS256, rsaKey
		res := e.runJWS(s.sign(t), true, false)
		if res.nextCalled || res.err == nil {
			t.Fatal("mismatched algorithm/key was accepted")
		}
		var pd *acme_controller.ProblemDetails
		if !errors.As(res.err, &pd) {
			t.Fatalf("expected ProblemDetails, got %v", res.err)
		}
		t.Logf("alg/key mismatch -> %d %s", pd.HTTPStatus, pd.Type)
		if pd.HTTPStatus == http.StatusInternalServerError {
			t.Errorf("client-controlled alg/key mismatch surfaced as internal server error")
		}
	})
}

func TestValidateJWS_Nonce(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.nonce = nil
		expectBadNonce(t, e.runJWS(s.sign(t), true, false))
	})

	t.Run("empty", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.nonce = sp("")
		expectBadNonce(t, e.runJWS(s.sign(t), true, false))
	})

	t.Run("garbage", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.nonce = sp("not-a-real-nonce")
		expectBadNonce(t, e.runJWS(s.sign(t), true, false))
	})

	// RFC 8555 6.5.2: a nonce that isn't valid base64url is a malformed JWS, not a badNonce
	for name, n := range map[string]string{
		"not base64":        "!!!@@@",
		"padded":            "abcd efgh=",
		"padding only":      "abc=",
		"standard base64":   "ab+/cd/+",
		"whitespace":        "abcd\nefgh",
		"impossible length": "abcde",
		"non-ascii":         "abcd\u00e9fgh",
	} {
		t.Run("invalid encoding: "+name, func(t *testing.T) {
			e := newJoseEnv(t)
			s := e.validSpec(t)
			s.nonce = sp(n)
			expectMalformed(t, e.runJWS(s.sign(t), true, false))
		})
	}

	t.Run("well-formed encoding but never issued is a badNonce", func(t *testing.T) {
		e := newJoseEnv(t)
		s := e.validSpec(t)
		s.nonce = sp(strings.Repeat("A", 96))
		expectBadNonce(t, e.runJWS(s.sign(t), true, false))
	})

	t.Run("replayed", func(t *testing.T) {
		e := newJoseEnv(t)
		body := e.validSpec(t).sign(t)
		if res := e.runJWS(body, true, false); res.err != nil {
			t.Fatal(res.err)
		}
		expectBadNonce(t, e.runJWS(body, true, false))
	})

	t.Run("from a different server instance", func(t *testing.T) {
		e := newJoseEnv(t)
		other := nonce.NewInMemCtrl()
		n, _ := other.Gen()
		s := e.validSpec(t)
		s.nonce = &n
		expectBadNonce(t, e.runJWS(s.sign(t), true, false))
	})

	t.Run("bad signature does not consume nonce", func(t *testing.T) {
		e := newJoseEnv(t)
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		s := e.validSpec(t)
		bad := s
		bad.key = otherKey
		_ = e.runJWS(bad.sign(t), true, false)
		if res := e.runJWS(s.sign(t), true, false); res.err != nil {
			t.Fatalf("legitimate request should still have a usable nonce: %v", res.err)
		}
	})
}

func TestValidateJWS_URL(t *testing.T) {
	tests := []struct {
		name string
		url  *string
	}{
		{"missing", nil},
		{"empty", sp("")},
		{"different endpoint", sp("https://example.com/acme/new-order")},
		{"different host", sp("https://evil.example.org/acme/new-account")},
		{"http instead of https", sp("http://example.com/acme/new-account")},
		{"trailing slash", sp("https://example.com/acme/new-account/")},
		{"query string appended", sp("https://example.com/acme/new-account?x=1")},
		{"relative path only", sp("/acme/new-account")},
		{"upper case", sp("https://example.com/ACME/NEW-ACCOUNT")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newJoseEnv(t)
			s := e.validSpec(t)
			s.url = tt.url

			res := e.runJWS(s.sign(t), true, false)
			if tt.url == nil {
				// RFC 8555 6.2 requires the header, so a JWS without one is malformed
				expectMalformed(t, res)
				return
			}
			// A url that doesn't match the request is unauthorized (RFC 8555 6.4)
			expectProblem(t, res, errUnauthorized, http.StatusForbidden)
		})
	}

	t.Run("url header is not a string", func(t *testing.T) {
		e := newJoseEnv(t)
		opts := (&jose.SignerOptions{}).WithHeader("nonce", e.nonce(t)).WithHeader("url", 123)
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: e.accKey, KeyID: e.accKID}}, opts)
		if err != nil {
			t.Fatal(err)
		}
		jws, _ := signer.Sign(nil)
		expectMalformed(t, e.runJWS(jws.FullSerialize(), true, false))
	})

	t.Run("request for a different path than signed", func(t *testing.T) {
		e := newJoseEnv(t)
		req := httptest.NewRequest(http.MethodPost, "/acme/new-order", strings.NewReader(e.validSpec(t).sign(t)))
		req.Header.Set("Content-Type", "application/jose+json")
		c := echo.New().NewContext(req, httptest.NewRecorder())
		called := false
		err := e.h.validateJWSAndExtractPayload(func(echo.Context) error { called = true; return nil }, c, true, false)
		if called {
			t.Fatal("next called")
		}
		var pd *acme_controller.ProblemDetails
		if !errors.As(err, &pd) || pd.Type != errUnauthorized || pd.HTTPStatus != http.StatusForbidden {
			t.Fatalf("got %v", err)
		}
	})
}

func TestValidateJWS_BodyReadFailure(t *testing.T) {
	e := newJoseEnv(t)
	req := httptest.NewRequest(http.MethodPost, reqURI, errReader{})
	req.Header.Set("Content-Type", "application/jose+json")
	c := echo.New().NewContext(req, httptest.NewRecorder())

	err := e.h.validateJWSAndExtractPayload(func(echo.Context) error { t.Fatal("next called"); return nil }, c, true, true)
	var pd *acme_controller.ProblemDetails
	if !errors.As(err, &pd) || pd.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("got %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestPOSTAsGETMw(t *testing.T) {
	h := Handlers{}

	tests := []struct {
		name      string
		payload   any
		wantNext  bool
		wantState int
	}{
		{"empty payload", []byte(""), true, 0},
		{"object payload", []byte("{}"), false, http.StatusBadRequest},
		{"whitespace payload", []byte(" "), false, http.StatusBadRequest},
		{"unset payload", nil, false, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
			if tt.payload != nil {
				c.Set(payloadBodyCtxKey, tt.payload)
			}
			called := false
			err := h.POSTAsGETMw(func(echo.Context) error { called = true; return nil })(c)
			if called != tt.wantNext {
				t.Fatalf("next called = %v, want %v (err %v)", called, tt.wantNext, err)
			}
			if !tt.wantNext {
				var pd *acme_controller.ProblemDetails
				if !errors.As(err, &pd) || pd.HTTPStatus != tt.wantState {
					t.Fatalf("got %v", err)
				}
			}
		})
	}
}
