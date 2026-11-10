package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

const (
	errBadCSR   = "urn:ietf:params:acme:error:badCSR"
	errInternal = "urn:ietf:params:acme:error:serverInternal"
	errNotReady = "urn:ietf:params:acme:error:orderNotReady"
)

// ctxOpts sets up an echo context as if the JWS middleware had already run.
type ctxOpts struct {
	method    string
	payload   []byte // nil leaves the payload unset on the context
	accountID []byte // nil leaves the account ID unset on the context
	header    *jose.Header
	params    map[string]string
}

func (e *joseEnv) ctx(o ctxOpts) (echo.Context, *httptest.ResponseRecorder) {
	if o.method == "" {
		o.method = http.MethodPost
	}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(o.method, "/", nil), rec)

	if o.payload != nil {
		c.Set(payloadBodyCtxKey, o.payload)
	}
	if o.accountID != nil {
		c.Set(accountIDCtxKey, o.accountID)
	}
	if o.header != nil {
		c.Set(protectedHeaderCtxKey, o.header)
	}
	if len(o.params) > 0 {
		names, values := []string{}, []string{}
		for k, v := range o.params {
			names, values = append(names, k), append(values, v)
		}
		c.SetParamNames(names...)
		c.SetParamValues(values...)
	}
	return c, rec
}

func (e *joseEnv) accountID() []byte {
	return []byte(strings.TrimPrefix(e.accKID, e.h.LinkCtrl.AccountPath("").Abs()))
}

func (e *joseEnv) newOtherAccount(t *testing.T) []byte {
	t.Helper()
	acc, err := e.h.AcmeCtrl.NewAccount(dtos.AccountRequestDTO{}, jose.JSONWebKey{Key: e.accKey.Public()})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(acc.ID)
}

func problem(t *testing.T, err error) *acme_controller.ProblemDetails {
	t.Helper()
	var pd *acme_controller.ProblemDetails
	if !errors.As(err, &pd) {
		t.Fatalf("expected ProblemDetails, got %T: %v", err, err)
	}
	return pd
}

func wantProblem(t *testing.T, err error, wantType string, wantStatus int) {
	t.Helper()
	pd := problem(t, err)
	if pd.Type != wantType || pd.HTTPStatus != wantStatus {
		t.Fatalf("got (%s, %d: %q), want (%s, %d)", pd.Type, pd.HTTPStatus, pd.Detail, wantType, wantStatus)
	}
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("invalid JSON body %q: %v", rec.Body.String(), err)
	}
	return v
}

func (e *joseEnv) makeOrder(t *testing.T, acc []byte, domains ...string) dtos.OrderResponseDTO {
	t.Helper()
	ids := []dtos.OrderIdentifierDTO{}
	for _, d := range domains {
		ids = append(ids, dtos.OrderIdentifierDTO{Type: "dns", Value: d})
	}
	body, _ := json.Marshal(dtos.OrderCreateRequestDTO{Identifiers: ids})
	c, rec := e.ctx(ctxOpts{payload: body, accountID: acc})
	if err := e.h.NewOrder(c); err != nil {
		t.Fatal(err)
	}
	return decode[dtos.OrderResponseDTO](t, rec)
}

func lastSegment(s string) string { return s[strings.LastIndex(s, "/")+1:] }

func TestGetNonce(t *testing.T) {
	e := newJoseEnv(t)

	tests := []struct {
		method     string
		wantStatus int
		wantErr    bool
	}{
		{http.MethodGet, http.StatusNoContent, false},
		{http.MethodHead, http.StatusOK, false},
		{http.MethodPost, 0, true},
		{http.MethodPut, 0, true},
		{http.MethodDelete, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			c, rec := e.ctx(ctxOpts{method: tt.method})
			err := e.h.GetNonce(c)
			if tt.wantErr {
				wantProblem(t, err, errMalformed, http.StatusMethodNotAllowed)
				return
			}
			if err != nil || rec.Code != tt.wantStatus {
				t.Fatalf("code=%d err=%v", rec.Code, err)
			}
			if rec.Body.Len() != 0 {
				t.Errorf("nonce responses must have an empty body, got %q", rec.Body.String())
			}
		})
	}
}

func TestAddNonce(t *testing.T) {
	e := newJoseEnv(t)

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		c, rec := e.ctx(ctxOpts{})
		called := false
		if err := e.h.AddNonceMw(func(echo.Context) error { called = true; return nil })(c); err != nil || !called {
			t.Fatalf("err=%v called=%v", err, called)
		}

		n := rec.Header().Get("Replay-Nonce")
		if n == "" || seen[n] {
			t.Fatalf("nonce %q empty or repeated", n)
		}
		seen[n] = true

		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", cc)
		}

		// The nonce handed out must be one the JWS validation would accept (once)
		if ok, err := e.h.NonceCtrl.ValidateAndConsume(n); !ok || err != nil {
			t.Errorf("issued nonce was not valid: ok=%v err=%v", ok, err)
		}
	}
}

type failingNonceCtrl struct{}

func (failingNonceCtrl) Gen() (string, error)                    { return "", errors.New("no entropy") }
func (failingNonceCtrl) ValidateAndConsume(string) (bool, error) { return false, nil }

func TestAddNonceFailure(t *testing.T) {
	e := newJoseEnv(t)
	e.h.NonceCtrl = failingNonceCtrl{}

	c, rec := e.ctx(ctxOpts{})
	err := e.h.AddNonceMw(func(echo.Context) error { t.Fatal("next called"); return nil })(c)
	wantProblem(t, err, errInternal, http.StatusInternalServerError)
	if rec.Header().Get("Replay-Nonce") != "" {
		t.Error("no nonce should be set on failure")
	}
}

func TestErrorHandler(t *testing.T) {
	e := newJoseEnv(t)
	app := echo.New()
	handler := e.h.ErrorHandler(app)

	t.Run("problem details", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{})
		handler(acme_controller.UnauthorizedProblem("nope"), c)

		if rec.Code != http.StatusForbidden {
			t.Errorf("code = %d", rec.Code)
		}
		body := decode[dtos.ProblemDTO](t, rec)
		if body.Type != errUnauthorized || body.Detail != "nope" || body.HTTPStatus != http.StatusForbidden {
			t.Errorf("body = %+v", body)
		}
	})

	// RFC 8555 6.7 / RFC 7807
	t.Run("problems are application/problem+json", func(t *testing.T) {
		for _, err := range []error{
			acme_controller.MalformedProblem("x"),
			acme_controller.InternalErrorProblem(errors.New("x")),
			errors.New("plain"),
			echo.ErrNotFound,
			echo.ErrMethodNotAllowed,
		} {
			c, rec := e.ctx(ctxOpts{})
			handler(err, c)
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("%v: Content-Type = %q", err, ct)
			}
		}
	})

	t.Run("wrapped problems are still recognised", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{})
		handler(fmt.Errorf("context: %w", acme_controller.BadNonceProblem("stale")), c)
		if rec.Code != http.StatusBadRequest || decode[dtos.ProblemDTO](t, rec).Type != "urn:ietf:params:acme:error:badNonce" {
			t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("internal problem does not leak the cause", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{})
		handler(acme_controller.InternalErrorProblem(errors.New("secret db path /var/lib/foo")), c)

		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unexpected plain error becomes a serverInternal problem with an id, without the cause", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{})
		handler(errors.New("boom"), c)

		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "boom") {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		body := decode[dtos.ProblemDTO](t, rec)
		if body.Type != errInternal || !strings.HasPrefix(body.Detail, "Error ID ") {
			t.Errorf("body = %+v", body)
		}
	})

	t.Run("echo not found and method not allowed become problems", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{})
		handler(echo.ErrNotFound, c)
		if rec.Code != http.StatusNotFound || decode[dtos.ProblemDTO](t, rec).Type != errMalformed {
			t.Errorf("not found: code=%d body=%s", rec.Code, rec.Body.String())
		}

		c, rec = e.ctx(ctxOpts{})
		handler(echo.ErrMethodNotAllowed, c)
		if rec.Code != http.StatusMethodNotAllowed || decode[dtos.ProblemDTO](t, rec).Type != errMalformed {
			t.Errorf("method not allowed: code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("other echo errors keep their status", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{})
		handler(echo.ErrNotImplemented, c)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("code = %d", rec.Code)
		}
	})

	t.Run("nothing is written once the response is committed", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{})
		c.NoContent(http.StatusNoContent)
		handler(acme_controller.MalformedProblem("late"), c)
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Errorf("code=%d body=%q", rec.Code, rec.Body.String())
		}
	})
}

func TestNewAccountHandler(t *testing.T) {
	e := newJoseEnv(t)
	jwk := &jose.JSONWebKey{Key: e.accKey.Public()}
	payload := []byte(`{"contact":["mailto:a@example.com"],"termsOfServiceAgreed":true}`)

	t.Run("success", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{payload: payload, header: &jose.Header{JSONWebKey: jwk}})
		if err := e.h.NewAccount(c); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusCreated {
			t.Errorf("code = %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "https://example.com/acme/account/") {
			t.Fatalf("Location = %q", loc)
		}
		body := decode[dtos.AccountResponseDTO](t, rec)
		if body.Status != "valid" || !body.TermsOfServiceAgreed || len(body.Contact) != 1 || body.OrdersURL != loc+"/orders" {
			t.Errorf("body = %+v", body)
		}

		// The account and its key must now exist under the advertised ID
		id := []byte(lastSegment(loc))
		if _, err := e.h.AcmeCtrl.GetAccountKey(id); err != nil {
			t.Errorf("account key not stored: %v", err)
		}
	})

	// RFC 8555 7.3: with terms of service published, agreement is mandatory
	t.Run("terms of service", func(t *testing.T) {
		withToS := *e
		withToS.h.LinkCtrl.MetaTosURL = "https://example.com/tos"

		for _, body := range []string{`{}`, `{"termsOfServiceAgreed":false}`, `{"contact":["mailto:a@example.com"]}`} {
			c, _ := withToS.ctx(ctxOpts{payload: []byte(body), header: &jose.Header{JSONWebKey: jwk}})
			wantProblem(t, withToS.h.NewAccount(c), errMalformed, http.StatusBadRequest)
		}

		c, rec := withToS.ctx(ctxOpts{payload: []byte(`{"termsOfServiceAgreed":true}`), header: &jose.Header{JSONWebKey: jwk}})
		if err := withToS.h.NewAccount(c); err != nil || rec.Code != http.StatusCreated {
			t.Errorf("agreeing should work: code=%d err=%v", rec.Code, err)
		}
	})

	t.Run("no terms of service published means agreement isn't required", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{payload: []byte(`{}`), header: &jose.Header{JSONWebKey: jwk}})
		if err := e.h.NewAccount(c); err != nil || rec.Code != http.StatusCreated {
			t.Errorf("code=%d err=%v", rec.Code, err)
		}
	})

	t.Run("invalid contacts", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte(`{"contact":["tel:+1555"]}`), header: &jose.Header{JSONWebKey: jwk}})
		wantProblem(t, e.h.NewAccount(c), "urn:ietf:params:acme:error:unsupportedContact", http.StatusBadRequest)

		c, _ = e.ctx(ctxOpts{payload: []byte(`{"contact":["mailto:nope"]}`), header: &jose.Header{JSONWebKey: jwk}})
		wantProblem(t, e.h.NewAccount(c), "urn:ietf:params:acme:error:invalidContact", http.StatusBadRequest)
	})

	t.Run("invalid json payload", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte("{"), header: &jose.Header{JSONWebKey: jwk}})
		wantProblem(t, e.h.NewAccount(c), errMalformed, http.StatusBadRequest)
	})

	t.Run("no jwk", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: payload, header: &jose.Header{KeyID: "x"}})
		wantProblem(t, e.h.NewAccount(c), errMalformed, http.StatusBadRequest)
	})

	t.Run("missing context values", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{header: &jose.Header{JSONWebKey: jwk}})
		wantProblem(t, e.h.NewAccount(c), errInternal, http.StatusInternalServerError)

		c, _ = e.ctx(ctxOpts{payload: payload})
		wantProblem(t, e.h.NewAccount(c), errInternal, http.StatusInternalServerError)
	})
}

func TestGetOrUpdateAccountHandler(t *testing.T) {
	e := newJoseEnv(t)
	acc := e.accountID()
	param := map[string]string{e.h.LinkCtrl.AccountIDParam(): string(acc)}

	t.Run("post-as-get", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{payload: []byte{}, accountID: acc, params: param})
		if err := e.h.GetOrUpdateAccount(c); err != nil {
			t.Fatal(err)
		}
		if body := decode[dtos.AccountResponseDTO](t, rec); body.Status != "valid" {
			t.Errorf("body = %+v", body)
		}
	})

	t.Run("update contact", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{payload: []byte(`{"contact":["mailto:new@example.com"]}`), accountID: acc, params: param})
		if err := e.h.GetOrUpdateAccount(c); err != nil {
			t.Fatal(err)
		}
		if body := decode[dtos.AccountResponseDTO](t, rec); len(body.Contact) != 1 || body.Contact[0] != "mailto:new@example.com" {
			t.Errorf("body = %+v", body)
		}
	})

	t.Run("update with invalid contact", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte(`{"contact":["http://example.com"]}`), accountID: acc, params: param})
		wantProblem(t, e.h.GetOrUpdateAccount(c), "urn:ietf:params:acme:error:unsupportedContact", http.StatusBadRequest)
	})

	t.Run("other account's id in url", func(t *testing.T) {
		other := e.newOtherAccount(t)
		for _, payload := range []string{"", `{"contact":["mailto:evil@example.com"]}`, `{"status":"deactivated"}`} {
			c, _ := e.ctx(ctxOpts{payload: []byte(payload), accountID: acc, params: map[string]string{e.h.LinkCtrl.AccountIDParam(): string(other)}})
			wantProblem(t, e.h.GetOrUpdateAccount(c), errUnauthorized, http.StatusForbidden)
		}
		if got, err := e.h.AcmeCtrl.GetAccount(other, other); err != nil || got.Status != "valid" || len(got.Contact) != 0 {
			t.Errorf("other account was modified: %+v, %v", got, err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte("{"), accountID: acc, params: param})
		wantProblem(t, e.h.GetOrUpdateAccount(c), errMalformed, http.StatusBadRequest)
	})

	t.Run("empty id param", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte{}, accountID: acc})
		wantProblem(t, e.h.GetOrUpdateAccount(c), errMalformed, http.StatusBadRequest)
	})

	t.Run("missing context values", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{accountID: acc, params: param})
		wantProblem(t, e.h.GetOrUpdateAccount(c), errInternal, http.StatusInternalServerError)
		c, _ = e.ctx(ctxOpts{payload: []byte{}, params: param})
		wantProblem(t, e.h.GetOrUpdateAccount(c), errInternal, http.StatusInternalServerError)
	})

	t.Run("deactivate", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{payload: []byte(`{"status":"deactivated"}`), accountID: acc, params: param})
		if err := e.h.GetOrUpdateAccount(c); err != nil {
			t.Fatal(err)
		}
		if body := decode[dtos.AccountResponseDTO](t, rec); body.Status != "deactivated" {
			t.Errorf("body = %+v", body)
		}
		if _, err := e.h.AcmeCtrl.GetAccountKey(acc); !db.IsErrNotFound(err) {
			t.Errorf("deactivated account's key should be gone, got %v", err)
		}
	})
}

func TestOrderHandlers(t *testing.T) {
	e := newJoseEnv(t)
	acc := e.accountID()
	other := e.newOtherAccount(t)

	t.Run("new order", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{payload: []byte(`{"identifiers":[{"type":"dns","value":"a.example.com"}]}`), accountID: acc})
		if err := e.h.NewOrder(c); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusCreated {
			t.Errorf("code = %d", rec.Code)
		}
		body := decode[dtos.OrderResponseDTO](t, rec)
		if body.Status != "pending" || len(body.AuthorizationURLs) != 1 || !strings.HasPrefix(body.FinalizeURL, "https://example.com/acme/order/") {
			t.Errorf("body = %+v", body)
		}
		// RFC 8555 7.1.3: there is no certificate to link to until the order is valid
		if raw := decode[map[string]any](t, rec); raw["certificate"] != nil {
			t.Errorf("pending order should not have a certificate URL, got %v", raw["certificate"])
		}
		if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://example.com/acme/order/") || strings.HasSuffix(loc, "/finalize") {
			t.Errorf("Location = %q", loc)
		}
	})

	t.Run("new order rejects bad input", func(t *testing.T) {
		for _, payload := range []string{"{", `{"identifiers":[{"type":"dns","value":""}]}`, `{"identifiers":[]}`, `{}`} {
			c, _ := e.ctx(ctxOpts{payload: []byte(payload), accountID: acc})
			wantProblem(t, e.h.NewOrder(c), errMalformed, http.StatusBadRequest)
		}

		c, _ := e.ctx(ctxOpts{payload: []byte(`{"identifiers":[{"type":"ip","value":"1.2.3.4"}]}`), accountID: acc})
		wantProblem(t, e.h.NewOrder(c), "urn:ietf:params:acme:error:unsupportedIdentifier", http.StatusBadRequest)
	})

	t.Run("new order without account", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte(`{}`)})
		wantProblem(t, e.h.NewOrder(c), errInternal, http.StatusInternalServerError)
	})

	order := e.makeOrder(t, acc, "b.example.com")
	orderID := lastSegment(strings.TrimSuffix(order.FinalizeURL, "/finalize"))
	orderParam := map[string]string{e.h.LinkCtrl.OrderIDParam(): orderID}

	t.Run("get order", func(t *testing.T) {
		c, rec := e.ctx(ctxOpts{payload: []byte{}, accountID: acc, params: orderParam})
		if err := e.h.GetOrder(c); err != nil {
			t.Fatal(err)
		}
		if body := decode[dtos.OrderResponseDTO](t, rec); body.Identifiers[0].Value != "b.example.com" {
			t.Errorf("body = %+v", body)
		}
	})

	t.Run("get order as another account", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte{}, accountID: other, params: orderParam})
		wantProblem(t, e.h.GetOrder(c), errUnauthorized, http.StatusForbidden)
	})

	t.Run("get order edge cases", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{accountID: acc})
		wantProblem(t, e.h.GetOrder(c), errMalformed, http.StatusBadRequest)

		c, _ = e.ctx(ctxOpts{params: orderParam})
		wantProblem(t, e.h.GetOrder(c), errInternal, http.StatusInternalServerError)

		c, _ = e.ctx(ctxOpts{accountID: acc, params: map[string]string{e.h.LinkCtrl.OrderIDParam(): "missing"}})
		wantProblem(t, e.h.GetOrder(c), errUnauthorized, http.StatusForbidden)
	})

	t.Run("orders list", func(t *testing.T) {
		param := map[string]string{e.h.LinkCtrl.AccountIDParam(): string(acc)}
		c, rec := e.ctx(ctxOpts{payload: []byte{}, accountID: acc, params: param})
		if err := e.h.GetOrdersByAccountID(c); err != nil {
			t.Fatal(err)
		}
		if body := decode[map[string]any](t, rec); body["orders"] == nil {
			t.Errorf("orders must be a JSON array, not null: %s", rec.Body.String())
		}

		c, _ = e.ctx(ctxOpts{payload: []byte{}, accountID: other, params: param})
		wantProblem(t, e.h.GetOrdersByAccountID(c), errUnauthorized, http.StatusForbidden)

		c, _ = e.ctx(ctxOpts{accountID: acc})
		wantProblem(t, e.h.GetOrdersByAccountID(c), errMalformed, http.StatusBadRequest)
	})
}

func TestFinalizeOrderHandlerRejections(t *testing.T) {
	e := newJoseEnv(t)
	acc := e.accountID()
	other := e.newOtherAccount(t)
	orderParamFor := func(order dtos.OrderResponseDTO) map[string]string {
		return map[string]string{e.h.LinkCtrl.OrderIDParam(): lastSegment(strings.TrimSuffix(order.FinalizeURL, "/finalize"))}
	}

	// Most cases need an order that is ready to finalize, so that it's the request that gets rejected
	order := e.makeOrder(t, acc, "a.example.com")
	for _, authzURL := range order.AuthorizationURLs {
		if _, err := e.db.UpdateAuthz([]byte(lastSegment(authzURL)), func(a *db.DBAuthz) error { a.Status = dtos.AuthzStatusValid; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	orderParam := orderParamFor(order)
	pendingParam := orderParamFor(e.makeOrder(t, acc, "pending.example.com"))

	tests := []struct {
		name       string
		payload    []byte
		account    []byte
		params     map[string]string
		wantType   string
		wantStatus int
	}{
		{"invalid json", []byte("{"), acc, orderParam, errMalformed, http.StatusBadRequest},
		{"order not ready", []byte(`{"csr":"AAAA"}`), acc, pendingParam, errNotReady, http.StatusForbidden},
		{"no order id", []byte(`{"csr":"AAAA"}`), acc, nil, errMalformed, http.StatusBadRequest},
		{"no account", []byte(`{"csr":"AAAA"}`), nil, orderParam, errInternal, http.StatusInternalServerError},
		{"other account", []byte(`{"csr":"AAAA"}`), other, orderParam, errUnauthorized, http.StatusForbidden},
		{"bad csr", []byte(`{"csr":"AAAA"}`), acc, orderParam, errBadCSR, http.StatusBadRequest},
		{"empty csr", []byte(`{}`), acc, orderParam, errBadCSR, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := e.ctx(ctxOpts{payload: tt.payload, accountID: tt.account, params: tt.params})
			wantProblem(t, e.h.FinalizeOrder(c), tt.wantType, tt.wantStatus)
		})
	}
}

func TestGetAuthorizationHandler(t *testing.T) {
	e := newJoseEnv(t)
	acc := e.accountID()
	other := e.newOtherAccount(t)
	order := e.makeOrder(t, acc, "a.example.com")
	authzID := lastSegment(order.AuthorizationURLs[0])
	param := map[string]string{e.h.LinkCtrl.AuthzIDParam(): authzID}

	c, rec := e.ctx(ctxOpts{payload: []byte{}, accountID: acc, params: param})
	if err := e.h.GetAuthorization(c); err != nil {
		t.Fatal(err)
	}
	body := decode[dtos.AuthzDTO](t, rec)
	if body.Status != "pending" || body.Identifier.Value != "a.example.com" || len(body.Challenges) != 1 || body.Challenges[0].Type != "http-01" {
		t.Errorf("body = %+v", body)
	}
	if want := "https://example.com/acme/chall/" + authzID + "00"; body.Challenges[0].URL != want {
		t.Errorf("challenge URL = %q, want %q", body.Challenges[0].URL, want)
	}
	if body.Expires == "" {
		t.Error("authz should carry an expiry")
	}

	// RFC 8555 7.1.4: "wildcard" must be absent unless it's true
	if raw := decode[map[string]any](t, rec); raw["wildcard"] != nil {
		t.Errorf("wildcard should be absent for a non-wildcard authz, got %v", raw["wildcard"])
	}

	c, _ = e.ctx(ctxOpts{payload: []byte{}, accountID: other, params: param})
	wantProblem(t, e.h.GetAuthorization(c), errUnauthorized, http.StatusForbidden)

	c, _ = e.ctx(ctxOpts{accountID: acc})
	wantProblem(t, e.h.GetAuthorization(c), errMalformed, http.StatusBadRequest)

	c, _ = e.ctx(ctxOpts{params: param})
	wantProblem(t, e.h.GetAuthorization(c), errInternal, http.StatusInternalServerError)
}

func TestInitiateChallengeHandlerRejections(t *testing.T) {
	e := newJoseEnv(t)
	acc := e.accountID()
	other := e.newOtherAccount(t)
	order := e.makeOrder(t, acc, "a.example.com")
	challID := lastSegment(order.AuthorizationURLs[0]) + "00"
	param := map[string]string{e.h.LinkCtrl.ChallengeIDParam(): challID}

	// RFC 8555 says the payload is "{}", but some clients send arbitrary objects; the handler only requires { ... }
	for _, payload := range []string{"", "[]", "null", "x", "{", "}", `"{}"`, "[{}]"} {
		t.Run("payload "+payload, func(t *testing.T) {
			c, _ := e.ctx(ctxOpts{payload: []byte(payload), accountID: acc, params: param})
			wantProblem(t, e.h.InitiateChallenge(c), errMalformed, http.StatusBadRequest)
		})
	}

	t.Run("missing challenge id", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte("{}"), accountID: acc})
		wantProblem(t, e.h.InitiateChallenge(c), errMalformed, http.StatusBadRequest)
	})
	t.Run("missing account", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte("{}"), params: param})
		wantProblem(t, e.h.InitiateChallenge(c), errInternal, http.StatusInternalServerError)
	})
	t.Run("missing payload", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{accountID: acc, params: param})
		wantProblem(t, e.h.InitiateChallenge(c), errInternal, http.StatusInternalServerError)
	})
	t.Run("other account", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte("{}"), accountID: other, params: param})
		wantProblem(t, e.h.InitiateChallenge(c), errUnauthorized, http.StatusForbidden)
	})
	t.Run("malformed id", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte("{}"), accountID: acc, params: map[string]string{e.h.LinkCtrl.ChallengeIDParam(): "x"}})
		wantProblem(t, e.h.InitiateChallenge(c), errMalformed, http.StatusBadRequest)
	})
	t.Run("unknown challenge index", func(t *testing.T) {
		c, _ := e.ctx(ctxOpts{payload: []byte("{}"), accountID: acc, params: map[string]string{e.h.LinkCtrl.ChallengeIDParam(): strings.TrimSuffix(challID, "00") + "05"}})
		wantProblem(t, e.h.InitiateChallenge(c), errMalformed, http.StatusNotFound)
	})
}

// RFC 8555 7.1: a challenge resource links to its authorization with rel="up". certbot's ACME library raises
// '"up" Link header missing' without it (found by running certbot against ACMESpider).
func TestInitiateChallengeHandlerLinksToAuthz(t *testing.T) {
	e := newJoseEnv(t)
	acc := e.accountID()
	order := e.makeOrder(t, acc, "a.example.com")
	authzID := lastSegment(order.AuthorizationURLs[0])
	challID := authzID + "00"

	// A challenge that's already valid is reported as-is, which lets this exercise the success response
	// without needing a real HTTP-01 target
	if _, err := e.db.UpdateAuthz([]byte(authzID), func(a *db.DBAuthz) error {
		a.Challenges[0].Status = dtos.ChallengeStatusValid
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	c, rec := e.ctx(ctxOpts{payload: []byte("{}"), accountID: acc, params: map[string]string{e.h.LinkCtrl.ChallengeIDParam(): challID}})
	if err := e.h.InitiateChallenge(c); err != nil {
		t.Fatal(err)
	}

	want := `<https://example.com/acme/authz/` + authzID + `>;rel="up"`
	links := rec.Header().Values("Link")
	if len(links) != 1 || links[0] != want {
		t.Errorf("Link headers = %q, want [%s]", links, want)
	}
	if body := decode[dtos.AuthzChallengeDTO](t, rec); body.Status != "valid" || !strings.HasSuffix(body.URL, "/chall/"+challID) {
		t.Errorf("body = %+v", body)
	}
}

func TestAddLinkAppends(t *testing.T) {
	e := newJoseEnv(t)
	c, rec := e.ctx(ctxOpts{})

	e.h.addLink(c, "https://example.com/acme/directory", "index")
	e.h.addLink(c, "https://example.com/acme/authz/x", "up")

	got := rec.Header().Values("Link")
	if len(got) != 2 || got[0] != `<https://example.com/acme/directory>;rel="index"` || got[1] != `<https://example.com/acme/authz/x>;rel="up"` {
		t.Errorf("Link headers = %q: a second link must not replace the first", got)
	}
}

func TestGetCertificateHandler(t *testing.T) {
	e := newJoseEnv(t)
	acc := e.accountID()
	other := e.newOtherAccount(t)

	const pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if err := e.db.CreateCertificate(db.DBCertificate{ID: "cert1", AccountID: string(acc), Certificate: []byte(pem)}); err != nil {
		t.Fatal(err)
	}
	param := map[string]string{e.h.LinkCtrl.CertIDParam(): "cert1"}

	c, rec := e.ctx(ctxOpts{payload: []byte{}, accountID: acc, params: param})
	if err := e.h.GetCertificate(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != pem {
		t.Errorf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("Content-Type = %q", ct)
	}

	c, _ = e.ctx(ctxOpts{payload: []byte{}, accountID: other, params: param})
	wantProblem(t, e.h.GetCertificate(c), errUnauthorized, http.StatusForbidden)

	c, _ = e.ctx(ctxOpts{payload: []byte{}, accountID: acc, params: map[string]string{e.h.LinkCtrl.CertIDParam(): "missing"}})
	wantProblem(t, e.h.GetCertificate(c), errUnauthorized, http.StatusForbidden)

	c, _ = e.ctx(ctxOpts{accountID: acc})
	wantProblem(t, e.h.GetCertificate(c), errMalformed, http.StatusBadRequest)

	c, _ = e.ctx(ctxOpts{params: param})
	wantProblem(t, e.h.GetCertificate(c), errInternal, http.StatusInternalServerError)
}
