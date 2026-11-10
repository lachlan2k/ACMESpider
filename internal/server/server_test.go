package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/lachlan2k/acmespider/internal/handlers"
	"github.com/lachlan2k/acmespider/internal/links"
	"github.com/lachlan2k/acmespider/internal/nonce"
)

type testServer struct {
	db     db.DB
	app    *echo.Echo
	links  links.LinkController
	ctrl   *acme_controller.ACMEController
	key    *ecdsa.PrivateKey
	kid    string
	accID  string
	handle handlers.Handlers
}

// newTestServer registers the real routes against a real DB. The lego client is nil, so only requests
// that don't reach the ACME authority can be served.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	d, err := db.NewBoltDb(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Seed(); err != nil {
		t.Fatal(err)
	}

	l := links.LinkController{BaseURL: "https://example.com/acme"}
	ctrl := acme_controller.New(d, nil, l)
	h := handlers.Handlers{AcmeCtrl: ctrl, NonceCtrl: nonce.NewInMemCtrl(), LinkCtrl: l}

	app := echo.New()
	registerRoutes(app, h, l)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := ctrl.NewAccount(dtos.AccountRequestDTO{}, jose.JSONWebKey{Key: key.Public()})
	if err != nil {
		t.Fatal(err)
	}

	return &testServer{db: d, app: app, links: l, ctrl: ctrl, key: key, kid: l.AccountPath(acc.ID).Abs(), accID: acc.ID, handle: h}
}

func (s *testServer) do(method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	s.app.ServeHTTP(rec, req)
	return rec
}

func (s *testServer) freshNonce(t *testing.T) string {
	t.Helper()

	rec := s.do(http.MethodHead, "/acme/new-nonce", "", "")
	n := rec.Header().Get("Replay-Nonce")
	if rec.Code != http.StatusOK || n == "" {
		t.Fatalf("new-nonce: code=%d nonce=%q", rec.Code, n)
	}
	return n
}

// signedRequest signs a POST-as-GET (empty payload) for the given request path using the account's KID.
func (s *testServer) signedRequest(t *testing.T, path string, nonceValue string) string {
	t.Helper()

	opts := (&jose.SignerOptions{}).WithHeader("nonce", nonceValue).WithHeader("url", "https://example.com"+path)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	return jws.FullSerialize()
}

func assertNonceHeaders(t *testing.T, rec *httptest.ResponseRecorder, context string) {
	t.Helper()

	if rec.Header().Get("Replay-Nonce") == "" {
		t.Errorf("%s: response (status %d) has no Replay-Nonce header", context, rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: Cache-Control = %q, want no-store", context, cc)
	}
}

// RFC 8555 6.5: servers SHOULD return a Replay-Nonce on error responses so clients can retry without a
// round trip to new-nonce. Walk the real route table so a newly added route can't forget the middleware,
// or put it after the JWS validation (which short-circuits on failure).
func TestEveryPOSTRouteReturnsNonceOnValidationFailure(t *testing.T) {
	s := newTestServer(t)

	checked := 0
	for _, route := range s.app.Routes() {
		if route.Method != http.MethodPost || !strings.HasPrefix(route.Path, "/acme/") {
			continue
		}
		path := route.Path
		for _, p := range []string{":" + s.links.AccountIDParam(), ":" + s.links.OrderIDParam(), ":" + s.links.AuthzIDParam(), ":" + s.links.ChallengeIDParam(), ":" + s.links.CertIDParam()} {
			path = strings.ReplaceAll(path, p, "x")
		}

		t.Run(route.Path, func(t *testing.T) {
			cases := map[string]struct {
				contentType string
				body        string
				wantStatus  int
			}{
				"wrong content type": {"application/json", "{}", http.StatusUnsupportedMediaType},
				"not a jws":          {"application/jose+json", "not json", http.StatusBadRequest},
				"empty body":         {"application/jose+json", "", http.StatusBadRequest},
			}
			for name, tc := range cases {
				rec := s.do(http.MethodPost, path, tc.contentType, tc.body)
				if rec.Code != tc.wantStatus {
					t.Errorf("%s: status = %d, want %d (%s)", name, rec.Code, tc.wantStatus, rec.Body.String())
				}
				assertNonceHeaders(t, rec, name)
				if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
					t.Errorf("%s: Content-Type = %q, want application/problem+json", name, ct)
				}
			}
		})
		checked++
	}

	if checked < 10 {
		t.Fatalf("only found %d POST routes, expected the full ACME API", checked)
	}
}

func TestAccountOrdersRouteNonceHandling(t *testing.T) {
	s := newTestServer(t)
	path := "/acme/account/" + s.accID + "/orders"

	t.Run("success returns the orders and a fresh nonce", func(t *testing.T) {
		n := s.freshNonce(t)
		rec := s.do(http.MethodPost, path, "application/jose+json", s.signedRequest(t, path, n))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		assertNonceHeaders(t, rec, "success")
		if got := rec.Header().Get("Replay-Nonce"); got == n {
			t.Error("response should carry a new nonce, not echo the consumed one")
		}

		var body struct {
			Orders []string `json:"orders"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Orders == nil {
			t.Errorf("orders must be a JSON array: %q (%v)", rec.Body.String(), err)
		}
	})

	t.Run("reused nonce is rejected with a replacement nonce", func(t *testing.T) {
		n := s.freshNonce(t)
		body := s.signedRequest(t, path, n)
		if rec := s.do(http.MethodPost, path, "application/jose+json", body); rec.Code != http.StatusOK {
			t.Fatalf("first request: status %d", rec.Code)
		}

		rec := s.do(http.MethodPost, path, "application/jose+json", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("replay: status = %d, want 400", rec.Code)
		}
		assertNonceHeaders(t, rec, "replayed nonce")
		// RFC 8555 6.5: clients key their retry logic off the badNonce type
		if !strings.Contains(rec.Body.String(), "urn:ietf:params:acme:error:badNonce") {
			t.Errorf("replayed nonce should be a badNonce, got %s", rec.Body.String())
		}

		// ...and that replacement nonce actually works for the retry
		retry := s.do(http.MethodPost, path, "application/jose+json", s.signedRequest(t, path, rec.Header().Get("Replay-Nonce")))
		if retry.Code != http.StatusOK {
			t.Errorf("retry with the nonce from the error response: status %d: %s", retry.Code, retry.Body.String())
		}
	})

	t.Run("non-empty payload is rejected, still with a nonce", func(t *testing.T) {
		opts := (&jose.SignerOptions{}).WithHeader("nonce", s.freshNonce(t)).WithHeader("url", "https://example.com"+path)
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}}, opts)
		jws, _ := signer.Sign([]byte("{}"))

		rec := s.do(http.MethodPost, path, "application/jose+json", jws.FullSerialize())
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		assertNonceHeaders(t, rec, "POST-as-GET violation")
	})
}

func TestNonPOSTRoutes(t *testing.T) {
	s := newTestServer(t)

	t.Run("directory", func(t *testing.T) {
		rec := s.do(http.MethodGet, "/acme/directory", "", "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "newAccount") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if link := rec.Header().Get("Link"); link != `<https://example.com/acme/directory>;rel="index"` {
			t.Errorf("Link = %q", link)
		}
		// Pre-authorization isn't implemented, so it must not be advertised (RFC 8555 7.1.1)
		if strings.Contains(rec.Body.String(), "newAuthz") {
			t.Errorf("directory advertises newAuthz: %s", rec.Body.String())
		}
	})

	t.Run("new-nonce", func(t *testing.T) {
		for method, want := range map[string]int{http.MethodGet: http.StatusNoContent, http.MethodHead: http.StatusOK} {
			rec := s.do(method, "/acme/new-nonce", "", "")
			if rec.Code != want {
				t.Errorf("%s: status = %d, want %d", method, rec.Code, want)
			}
			assertNonceHeaders(t, rec, method)
		}
	})
}

// RFC 8555 6.3 / 7.4: clients fetch an order with a POST-as-GET. The order URL defines no other operation,
// so a request with a payload is refused.
func TestOrderRouteIsPOSTAsGET(t *testing.T) {
	s := newTestServer(t)

	order, err := s.ctrl.NewOrder(dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{{Type: "dns", Value: "a.example.com"}}}, []byte(s.accID))
	if err != nil {
		t.Fatal(err)
	}
	path := "/acme/order/" + order.ID

	post := func(payload string) *httptest.ResponseRecorder {
		opts := (&jose.SignerOptions{}).WithHeader("nonce", s.freshNonce(t)).WithHeader("url", "https://example.com"+path)
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}}, opts)
		jws, _ := signer.Sign([]byte(payload))
		return s.do(http.MethodPost, path, "application/jose+json", jws.FullSerialize())
	}

	if rec := post(""); rec.Code != http.StatusOK {
		t.Fatalf("POST-as-GET: status = %d: %s", rec.Code, rec.Body.String())
	}

	rec := post("{}")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("payload on the order route: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	assertNonceHeaders(t, rec, "order with payload")
}

func TestUnknownRouteIsAProblemDocument(t *testing.T) {
	s := newTestServer(t)

	rec := s.do(http.MethodGet, "/acme/nope", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), `"type":"urn:ietf:params:acme:error:malformed"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// Through the real routes, a challenge response carries both the index link and the "up" link to its authorization
func TestChallengeResponseLinks(t *testing.T) {
	s := newTestServer(t)

	order, err := s.ctrl.NewOrder(dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{{Type: "dns", Value: "a.example.com"}}}, []byte(s.accID))
	if err != nil {
		t.Fatal(err)
	}
	authzID := order.AuthzIDs[0]
	path := "/acme/chall/" + authzID + "00"

	// Already-answered challenges are reported as they are, so no real validation target is needed
	if _, err := s.db.UpdateAuthz([]byte(authzID), func(a *db.DBAuthz) error {
		a.Challenges[0].Status = dtos.ChallengeStatusValid
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	opts := (&jose.SignerOptions{}).WithHeader("nonce", s.freshNonce(t)).WithHeader("url", "https://example.com"+path)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}}, opts)
	jws, _ := signer.Sign([]byte("{}"))
	rec := s.do(http.MethodPost, path, "application/jose+json", jws.FullSerialize())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	links := strings.Join(rec.Header().Values("Link"), " | ")
	for _, want := range []string{`<https://example.com/acme/directory>;rel="index"`, `<https://example.com/acme/authz/` + authzID + `>;rel="up"`} {
		if !strings.Contains(links, want) {
			t.Errorf("Link headers %q are missing %s", links, want)
		}
	}
}
