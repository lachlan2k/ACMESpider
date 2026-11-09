package acme_controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

func TestNewOrder(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)

	before := time.Now()
	order, err := ac.NewOrder(dtos.OrderCreateRequestDTO{
		Identifiers: []dtos.OrderIdentifierDTO{{Type: "dns", Value: "a.example.com"}, {Type: "dns", Value: "b.example.com"}},
		NotBefore:   "2030-01-02T03:04:05Z",
		NotAfter:    "2031-01-02T03:04:05Z",
	}, acc)
	if err != nil {
		t.Fatal(err)
	}

	if order.Status != dtos.OrderStatusPending || order.AccountID != string(acc) || order.CertificateID != "" {
		t.Errorf("unexpected order: %+v", order)
	}
	if exp := time.Unix(order.Expires, 0); exp.Before(before) || exp.After(before.Add(orderExpiryTime+time.Minute)) {
		t.Errorf("unexpected expiry %v", exp)
	}
	if order.NotBefore == nil || *order.NotBefore != time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC).Unix() {
		t.Errorf("unexpected notBefore %v", order.NotBefore)
	}
	if order.NotAfter == nil || *order.NotAfter != time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC).Unix() {
		t.Errorf("unexpected notAfter %v", order.NotAfter)
	}
	if len(order.Identifiers) != 2 || len(order.AuthzIDs) != 2 {
		t.Fatalf("expected 2 identifiers and authzs: %+v", order)
	}

	// The order should be persisted, with one pending authz + http-01 challenge per identifier
	stored, err := ac.db.GetOrder([]byte(order.ID))
	if err != nil || stored.ID != order.ID {
		t.Fatalf("order not persisted: %v", err)
	}

	tokens := map[string]bool{}
	for i, authzID := range order.AuthzIDs {
		authz, err := ac.db.GetAuthz([]byte(authzID))
		if err != nil {
			t.Fatal(err)
		}
		if authz.OrderID != order.ID || authz.AccountID != string(acc) || authz.Status != dtos.AuthzStatusPending {
			t.Errorf("unexpected authz: %+v", authz)
		}
		if authz.Identifier != order.Identifiers[i] {
			t.Errorf("authz identifier %+v doesn't match order identifier %+v", authz.Identifier, order.Identifiers[i])
		}
		if len(authz.Challenges) != 1 {
			t.Fatalf("got %d challenges", len(authz.Challenges))
		}
		ch := authz.Challenges[0]
		if ch.Type != HTTP01ChallengeType || ch.Status != dtos.ChallengeStatusPending || ch.ID != authzID+"00" {
			t.Errorf("unexpected challenge: %+v", ch)
		}
		if len(ch.Token) < 32 || tokens[ch.Token] {
			t.Errorf("challenge token %q is short or not unique", ch.Token)
		}
		tokens[ch.Token] = true
	}
}

func TestNewOrderRejectsInvalidInput(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)
	good := dtos.OrderIdentifierDTO{Type: "dns", Value: "a.example.com"}

	tests := []struct {
		name    string
		payload dtos.OrderCreateRequestDTO
	}{
		{"empty value", dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{{Type: "dns", Value: ""}}}},
		{"empty value among valid", dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{good, {Type: "dns"}}}},
		{"empty type", dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{{Value: "a.example.com"}}}},
		{"bad notBefore", dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{good}, NotBefore: "tomorrow"}},
		{"bad notAfter", dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{good}, NotAfter: "2030-01-01"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order, err := ac.NewOrder(tt.payload, acc)
			if err == nil {
				t.Fatalf("expected error, got order %+v", order)
			}
			expectProblem(t, err, malformedErr, http.StatusBadRequest)
		})
	}
}

// RFC 8555 6.7: an identifier of a type we don't handle is unsupportedIdentifier, not just malformed
func TestNewOrderUnsupportedIdentifierType(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)

	for _, idType := range []string{"ip", "email", "DNS", "dns "} {
		_, err := ac.NewOrder(dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{{Type: idType, Value: "a.example.com"}}}, acc)
		expectProblem(t, err, unsupportedIdentifierErr, http.StatusBadRequest)
	}
}

// RFC 8555 7.5.1: an authz that becomes valid must have an expiry
func TestNewOrderAuthzsHaveExpiry(t *testing.T) {
	ac := newTestCtrl(t)
	order := ac.newTestOrder(t, ac.newTestAccount(t), "a.example.com", "b.example.com")

	for _, id := range order.AuthzIDs {
		authz, err := ac.db.GetAuthz([]byte(id))
		if err != nil {
			t.Fatal(err)
		}
		if authz.ExpireValidityTime == nil || *authz.ExpireValidityTime != order.Expires {
			t.Errorf("authz expiry = %v, want the order's expiry %d", authz.ExpireValidityTime, order.Expires)
		}
	}
}

// RFC 8555 7.4 marks "identifiers" required but doesn't forbid an empty list; we reject it as policy.
// With zero identifiers there are no
// authorizations to validate, so the order would immediately count as ready.
func TestNewOrderRejectsNoIdentifiers(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)

	for name, ids := range map[string][]dtos.OrderIdentifierDTO{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			order, err := ac.NewOrder(dtos.OrderCreateRequestDTO{Identifiers: ids}, acc)
			if err == nil {
				t.Fatalf("order with no identifiers was accepted: %+v", order)
			}
			expectProblem(t, err, malformedErr, http.StatusBadRequest)
		})
	}
}

func TestGetOrder(t *testing.T) {
	ac := newTestCtrl(t)
	owner := ac.newTestAccount(t)
	other := ac.newTestAccount(t)
	order := ac.newTestOrder(t, owner, "a.example.com")

	got, err := ac.GetOrder([]byte(order.ID), owner)
	if err != nil || got.ID != order.ID {
		t.Fatalf("got %+v, %v", got, err)
	}

	// Don't reveal whether an order exists: wrong owner and missing are indistinguishable
	_, err = ac.GetOrder([]byte(order.ID), other)
	expectUnauthorized(t, err)
	_, err = ac.GetOrder([]byte("missing"), owner)
	expectUnauthorized(t, err)
}

func TestGetOrderRecomputesStatus(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)
	order := ac.newTestOrder(t, acc, "a.example.com", "b.example.com")

	got, _ := ac.GetOrder([]byte(order.ID), acc)
	if got.Status != dtos.OrderStatusPending {
		t.Fatalf("status = %s, want pending", got.Status)
	}

	ac.markAuthzValid(t, order.AuthzIDs[0])
	got, _ = ac.GetOrder([]byte(order.ID), acc)
	if got.Status != dtos.OrderStatusPending {
		t.Fatalf("one authz valid: status = %s, want pending", got.Status)
	}

	ac.markAuthzValid(t, order.AuthzIDs[1])
	got, _ = ac.GetOrder([]byte(order.ID), acc)
	if got.Status != dtos.OrderStatusReady {
		t.Fatalf("all authzs valid: status = %s, want ready", got.Status)
	}
}

func TestRecomputeOrderStatus(t *testing.T) {
	setExpires := func(t *testing.T, ac *ACMEController, id string, at time.Time) {
		t.Helper()
		_, err := ac.db.UpdateOrder([]byte(id), func(o *db.DBOrder) error {
			o.Expires = at.Unix()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	status := func(t *testing.T, ac *ACMEController, id string) string {
		t.Helper()
		o, err := ac.db.GetOrder([]byte(id))
		if err != nil {
			t.Fatal(err)
		}
		return o.Status
	}

	t.Run("missing order", func(t *testing.T) {
		ac := newTestCtrl(t)
		if err := ac.recomputeOrderStatus([]byte("missing")); !db.IsErrNotFound(err) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("expired with pending authz becomes invalid", func(t *testing.T) {
		ac := newTestCtrl(t)
		order := ac.newTestOrder(t, ac.newTestAccount(t), "a.example.com")
		setExpires(t, ac, order.ID, time.Now().Add(-time.Minute))

		if err := ac.recomputeOrderStatus([]byte(order.ID)); err != nil {
			t.Fatal(err)
		}
		// RFC 8555 7.1.6: an order that expires moves to invalid ("expired" isn't an order status)
		if s := status(t, ac, order.ID); s != dtos.OrderStatusInvalid {
			t.Errorf("status = %s, want invalid", s)
		}
	})

	t.Run("expired with all authz valid becomes invalid, not ready", func(t *testing.T) {
		ac := newTestCtrl(t)
		order := ac.newTestOrder(t, ac.newTestAccount(t), "a.example.com")
		ac.markAuthzValid(t, order.AuthzIDs[0])
		setExpires(t, ac, order.ID, time.Now().Add(-time.Minute))

		if err := ac.recomputeOrderStatus([]byte(order.ID)); err != nil {
			t.Fatal(err)
		}
		// RFC 8555 7.1.6: an order that expires moves to invalid ("expired" isn't an order status)
		if s := status(t, ac, order.ID); s != dtos.OrderStatusInvalid {
			t.Errorf("status = %s, want invalid", s)
		}
	})

	for _, s := range []string{dtos.OrderStatusProcessing, dtos.OrderStatusValid, dtos.OrderStatusInvalid, dtos.OrderStatusReady} {
		t.Run("non-pending status untouched: "+s, func(t *testing.T) {
			ac := newTestCtrl(t)
			order := ac.newTestOrder(t, ac.newTestAccount(t), "a.example.com")
			ac.markAuthzValid(t, order.AuthzIDs[0])
			ac.db.UpdateOrder([]byte(order.ID), func(o *db.DBOrder) error { o.Status = s; return nil })

			if err := ac.recomputeOrderStatus([]byte(order.ID)); err != nil {
				t.Fatal(err)
			}
			if got := status(t, ac, order.ID); got != s {
				t.Errorf("status = %s, want %s", got, s)
			}
		})
	}

	// RFC 8555 7.1.6: an authz in a final state other than valid makes the order invalid
	for _, authzStatus := range []string{dtos.AuthzStatusInvalid, dtos.AuthzStatusExpired, dtos.AuthzStatusRevoked, dtos.AuthzStatusDeactivated} {
		t.Run("authz "+authzStatus+" makes the order invalid", func(t *testing.T) {
			ac := newTestCtrl(t)
			order := ac.newTestOrder(t, ac.newTestAccount(t), "a.example.com", "b.example.com")
			ac.markAuthzValid(t, order.AuthzIDs[0])
			ac.db.UpdateAuthz([]byte(order.AuthzIDs[1]), func(a *db.DBAuthz) error { a.Status = authzStatus; return nil })

			if err := ac.recomputeOrderStatus([]byte(order.ID)); err != nil {
				t.Fatal(err)
			}
			if s := status(t, ac, order.ID); s != dtos.OrderStatusInvalid {
				t.Errorf("status = %s, want invalid", s)
			}
		})
	}

	t.Run("pending authz alongside valid ones keeps the order pending", func(t *testing.T) {
		ac := newTestCtrl(t)
		order := ac.newTestOrder(t, ac.newTestAccount(t), "a.example.com", "b.example.com")
		ac.markAuthzValid(t, order.AuthzIDs[0])

		ac.recomputeOrderStatus([]byte(order.ID))
		if s := status(t, ac, order.ID); s != dtos.OrderStatusPending {
			t.Errorf("status = %s, want pending", s)
		}
	})
}

func TestGetOrdersByAccountID(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)
	other := ac.newTestAccount(t)

	orders, err := ac.GetOrdersByAccountID(acc, acc)
	if err != nil || orders == nil || len(orders) != 0 {
		t.Fatalf("new account should have an empty non-nil list, got %v, %v", orders, err)
	}

	_, err = ac.GetOrdersByAccountID(acc, other)
	expectUnauthorized(t, err)

	first := ac.newTestOrder(t, acc, "a.example.com")
	second := ac.newTestOrder(t, acc, "b.example.com")
	otherOrder := ac.newTestOrder(t, other, "c.example.com")

	want := []string{ac.linkCtrl.OrderPath(first.ID).Abs(), ac.linkCtrl.OrderPath(second.ID).Abs()}
	orders, err = ac.GetOrdersByAccountID(acc, acc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(orders, want) {
		t.Errorf("orders = %v, want %v", orders, want)
	}

	// Each account only sees its own orders
	orders, err = ac.GetOrdersByAccountID(other, other)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{ac.linkCtrl.OrderPath(otherOrder.ID).Abs()}; !reflect.DeepEqual(orders, want) {
		t.Errorf("other account's orders = %v, want %v", orders, want)
	}
}

func TestConcurrentOrdersAreAllListed(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ac.NewOrder(dtos.OrderCreateRequestDTO{Identifiers: []dtos.OrderIdentifierDTO{{Type: "dns", Value: "a.example.com"}}}, acc); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	orders, err := ac.GetOrdersByAccountID(acc, acc)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != n {
		t.Errorf("got %d orders listed, want %d (updates were lost)", len(orders), n)
	}
}

func TestGetAuthorization(t *testing.T) {
	ac := newTestCtrl(t)
	owner := ac.newTestAccount(t)
	other := ac.newTestAccount(t)
	order := ac.newTestOrder(t, owner, "a.example.com")

	got, err := ac.GetAuthorization([]byte(order.AuthzIDs[0]), owner)
	if err != nil || got.ID != order.AuthzIDs[0] {
		t.Fatalf("got %+v, %v", got, err)
	}

	_, err = ac.GetAuthorization([]byte(order.AuthzIDs[0]), other)
	expectUnauthorized(t, err)
	_, err = ac.GetAuthorization([]byte("missing"), owner)
	expectUnauthorized(t, err)
}

func TestGetCertificate(t *testing.T) {
	ac := newTestCtrl(t)
	owner := ac.newTestAccount(t)
	other := ac.newTestAccount(t)

	if err := ac.db.CreateCertificate(db.DBCertificate{ID: "c1", AccountID: string(owner), Certificate: []byte("PEM")}); err != nil {
		t.Fatal(err)
	}

	got, err := ac.GetCertificate(owner, []byte("c1"))
	if err != nil || string(got) != "PEM" {
		t.Fatalf("got %q, %v", got, err)
	}

	_, err = ac.GetCertificate(other, []byte("c1"))
	expectUnauthorized(t, err)
	_, err = ac.GetCertificate(owner, []byte("missing"))
	expectUnauthorized(t, err)
}

type csrOpts struct {
	cn    string
	dns   []string
	ips   []net.IP
	email []string
}

func csrFromOpts(t *testing.T, o csrOpts) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{DNSNames: o.dns, IPAddresses: o.ips, EmailAddresses: o.email}
	if o.cn != "" {
		tmpl.Subject = pkix.Name{CommonName: o.cn}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func b64CSR(der []byte) string { return base64.RawURLEncoding.EncodeToString(der) }

// testCSR makes a CSR with the first name as the common name and every name in the SAN extension
func testCSR(t *testing.T, names ...string) string {
	t.Helper()
	return b64CSR(csrFromOpts(t, csrOpts{cn: names[0], dns: names}))
}

// readyOrder creates an order for the domains with every authz valid, and moves it to ready
func (ac *ACMEController) readyOrder(t *testing.T, acc []byte, domains ...string) *db.DBOrder {
	t.Helper()

	order := ac.newTestOrder(t, acc, domains...)
	for _, id := range order.AuthzIDs {
		ac.markAuthzValid(t, id)
	}
	got, err := ac.GetOrder([]byte(order.ID), acc)
	if err != nil || got.Status != dtos.OrderStatusReady {
		t.Fatalf("order should be ready: %+v, %v", got, err)
	}
	return got
}

func TestValidateCSRForOrder(t *testing.T) {
	order := &db.DBOrder{Identifiers: []db.DBOrderIdentifier{{Type: "dns", Value: "a.example.com"}, {Type: "dns", Value: "b.example.com"}}}

	parse := func(o csrOpts) *x509.CertificateRequest {
		csr, err := x509.ParseCertificateRequest(csrFromOpts(t, o))
		if err != nil {
			t.Fatal(err)
		}
		return csr
	}

	tests := []struct {
		name    string
		csr     csrOpts
		wantErr bool
	}{
		{"SAN only", csrOpts{dns: []string{"a.example.com", "b.example.com"}}, false},
		{"SAN only, other order", csrOpts{dns: []string{"b.example.com", "a.example.com"}}, false},
		{"SAN and CN", csrOpts{cn: "a.example.com", dns: []string{"a.example.com", "b.example.com"}}, false},
		{"CN is the second name", csrOpts{cn: "b.example.com", dns: []string{"a.example.com", "b.example.com"}}, false},
		{"CN covers one name, SAN the other", csrOpts{cn: "a.example.com", dns: []string{"b.example.com"}}, false},
		{"case differences", csrOpts{dns: []string{"A.Example.COM", "b.EXAMPLE.com"}}, false},
		{"duplicate SAN entries", csrOpts{dns: []string{"a.example.com", "a.example.com", "b.example.com"}}, false},

		{"missing a name", csrOpts{dns: []string{"a.example.com"}}, true},
		{"extra name", csrOpts{dns: []string{"a.example.com", "b.example.com", "c.example.com"}}, true},
		{"completely different name", csrOpts{dns: []string{"evil.example.org"}}, true},
		{"right names plus extra CN", csrOpts{cn: "evil.example.org", dns: []string{"a.example.com", "b.example.com"}}, true},
		{"CN only, missing a name", csrOpts{cn: "a.example.com"}, true},
		{"no names at all", csrOpts{}, true},
		{"subdomain of requested name", csrOpts{dns: []string{"x.a.example.com", "b.example.com"}}, true},
		{"wildcard where a name was requested", csrOpts{dns: []string{"*.example.com", "b.example.com"}}, true},
		{"right names plus IP", csrOpts{dns: []string{"a.example.com", "b.example.com"}, ips: []net.IP{net.ParseIP("10.0.0.1")}}, true},
		{"right names plus email", csrOpts{dns: []string{"a.example.com", "b.example.com"}, email: []string{"a@example.com"}}, true},
		{"trailing dot differs", csrOpts{dns: []string{"a.example.com.", "b.example.com"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCSRForOrder(parse(tt.csr), order)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			expectProblem(t, err, badCSRErr, http.StatusBadRequest)
		})
	}

	t.Run("wildcard order accepts the same wildcard", func(t *testing.T) {
		wild := &db.DBOrder{Identifiers: []db.DBOrderIdentifier{{Type: "dns", Value: "*.example.com"}}}
		if err := validateCSRForOrder(parse(csrOpts{dns: []string{"*.example.com"}}), wild); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParseCSR(t *testing.T) {
	valid := csrFromOpts(t, csrOpts{dns: []string{"a.example.com"}})

	if _, err := parseCSR(b64CSR(valid)); err != nil {
		t.Fatalf("valid CSR rejected: %v", err)
	}

	// The last bytes of the DER are the signature, so flipping one leaves a parseable CSR with a bad signature
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 0xff

	tests := map[string]string{
		"not base64":        "!!!",
		"padded base64":     b64CSR(valid) + "==",
		"empty":             "",
		"not der":           b64CSR([]byte("not a csr")),
		"invalid signature": b64CSR(tampered),
		"trailing data":     b64CSR(append(append([]byte(nil), valid...), 0x00)),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseCSR(in)
			expectProblem(t, err, badCSRErr, http.StatusBadRequest)
		})
	}
}

// Only rejections are covered here: a successful finalize starts a goroutine that calls the (nil here) lego client.
func TestFinalizeOrderRejections(t *testing.T) {
	ac := newTestCtrl(t)
	owner := ac.newTestAccount(t)
	other := ac.newTestAccount(t)
	order := ac.readyOrder(t, owner, "a.example.com")
	validCSR := testCSR(t, "a.example.com")

	tests := []struct {
		name       string
		orderID    string
		account    []byte
		csr        string
		wantType   string
		wantStatus int
	}{
		{"unknown order", "missing", owner, validCSR, unauthorizedErr, http.StatusForbidden},
		{"other account's order", order.ID, other, validCSR, unauthorizedErr, http.StatusForbidden},
		{"csr not base64", order.ID, owner, "!!!", badCSRErr, http.StatusBadRequest},
		{"csr with padding", order.ID, owner, validCSR + "==", badCSRErr, http.StatusBadRequest},
		{"csr empty", order.ID, owner, "", badCSRErr, http.StatusBadRequest},
		{"csr not der", order.ID, owner, b64CSR([]byte("not a csr")), badCSRErr, http.StatusBadRequest},
		{"csr for a different name", order.ID, owner, testCSR(t, "evil.example.org"), badCSRErr, http.StatusBadRequest},
		{"csr with an extra name", order.ID, owner, testCSR(t, "a.example.com", "b.example.com"), badCSRErr, http.StatusBadRequest},
		{"csr with no names", order.ID, owner, b64CSR(csrFromOpts(t, csrOpts{})), badCSRErr, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ac.FinalizeOrder([]byte(tt.orderID), dtos.OrderFinalizeRequestDTO{CSRB64: tt.csr}, tt.account)
			expectProblem(t, err, tt.wantType, tt.wantStatus)

			// RFC 8555 7.4: after a badCSR the order stays ready so the client can retry
			got, _ := ac.db.GetOrder([]byte(order.ID))
			if got.Status != dtos.OrderStatusReady {
				t.Errorf("rejected finalize changed order status to %s", got.Status)
			}
		})
	}
}

// RFC 8555 7.4: finalizing an order that isn't ready is a 403 orderNotReady. Without this check a second
// finalize would start another issuance and an expired order could still be issued.
func TestFinalizeOrderRequiresReady(t *testing.T) {
	validCSR := testCSR(t, "a.example.com")

	t.Run("authz still pending", func(t *testing.T) {
		ac := newTestCtrl(t)
		acc := ac.newTestAccount(t)
		order := ac.newTestOrder(t, acc, "a.example.com")

		_, err := ac.FinalizeOrder([]byte(order.ID), dtos.OrderFinalizeRequestDTO{CSRB64: validCSR}, acc)
		expectProblem(t, err, orderNotReadyErr, http.StatusForbidden)
	})

	// All authzs are valid in every case below, so only the order's status can stop the finalize
	for _, status := range []string{dtos.OrderStatusProcessing, dtos.OrderStatusValid, dtos.OrderStatusInvalid} {
		t.Run("status "+status, func(t *testing.T) {
			ac := newTestCtrl(t)
			acc := ac.newTestAccount(t)
			order := ac.readyOrder(t, acc, "a.example.com")
			ac.db.UpdateOrder([]byte(order.ID), func(o *db.DBOrder) error { o.Status = status; return nil })

			_, err := ac.FinalizeOrder([]byte(order.ID), dtos.OrderFinalizeRequestDTO{CSRB64: validCSR}, acc)
			expectProblem(t, err, orderNotReadyErr, http.StatusForbidden)

			if got, _ := ac.db.GetOrder([]byte(order.ID)); got.Status != status {
				t.Errorf("status changed from %s to %s", status, got.Status)
			}
		})
	}

	t.Run("ready order that has since expired", func(t *testing.T) {
		ac := newTestCtrl(t)
		acc := ac.newTestAccount(t)
		order := ac.readyOrder(t, acc, "a.example.com")
		ac.db.UpdateOrder([]byte(order.ID), func(o *db.DBOrder) error { o.Expires = time.Now().Add(-time.Minute).Unix(); return nil })

		_, err := ac.FinalizeOrder([]byte(order.ID), dtos.OrderFinalizeRequestDTO{CSRB64: validCSR}, acc)
		expectProblem(t, err, orderNotReadyErr, http.StatusForbidden)

		if got, _ := ac.db.GetOrder([]byte(order.ID)); got.Status != dtos.OrderStatusInvalid {
			t.Errorf("status = %s, want invalid", got.Status)
		}
	})

	t.Run("not ready is reported before the csr is looked at", func(t *testing.T) {
		ac := newTestCtrl(t)
		acc := ac.newTestAccount(t)
		order := ac.newTestOrder(t, acc, "a.example.com")

		_, err := ac.FinalizeOrder([]byte(order.ID), dtos.OrderFinalizeRequestDTO{CSRB64: "!!!"}, acc)
		expectProblem(t, err, orderNotReadyErr, http.StatusForbidden)
	})
}

func TestMarkOrderProcessingIsExclusive(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)
	order := ac.readyOrder(t, acc, "a.example.com")

	const workers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners, notReady := 0, 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ac.markOrderProcessing([]byte(order.ID))

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
			case problemOf(t, err).Type == orderNotReadyErr:
				notReady++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if winners != 1 || notReady != workers-1 {
		t.Errorf("winners=%d notReady=%d, want exactly 1 winner and %d orderNotReady", winners, notReady, workers-1)
	}
	if got, _ := ac.db.GetOrder([]byte(order.ID)); got.Status != dtos.OrderStatusProcessing {
		t.Errorf("status = %s", got.Status)
	}
}

func TestMarkOrderProcessingMissingOrder(t *testing.T) {
	ac := newTestCtrl(t)
	if _, err := ac.markOrderProcessing([]byte("missing")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestReadyOrderExpires(t *testing.T) {
	ac := newTestCtrl(t)
	acc := ac.newTestAccount(t)
	order := ac.readyOrder(t, acc, "a.example.com")

	// Still within its lifetime: stays ready
	if err := ac.recomputeOrderStatus([]byte(order.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := ac.db.GetOrder([]byte(order.ID)); got.Status != dtos.OrderStatusReady {
		t.Fatalf("status = %s, want ready", got.Status)
	}

	ac.db.UpdateOrder([]byte(order.ID), func(o *db.DBOrder) error { o.Expires = time.Now().Add(-time.Second).Unix(); return nil })
	if err := ac.recomputeOrderStatus([]byte(order.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := ac.db.GetOrder([]byte(order.ID)); got.Status != dtos.OrderStatusInvalid {
		t.Fatalf("status = %s, want invalid", got.Status)
	}
}
