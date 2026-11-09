package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v3"
)

func newTestDB(t *testing.T) DB {
	t.Helper()

	d, err := NewBoltDb(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.(*BoltDB).db.Close() })

	if err := d.Seed(); err != nil {
		t.Fatal(err)
	}
	return d
}

func testJWK(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &jose.JSONWebKey{Key: key.Public(), Algorithm: "ES256", Use: "sig"}
}

func ptr[T any](v T) *T { return &v }

func TestSeedTwiceFails(t *testing.T) {
	d := newTestDB(t)
	if err := d.Seed(); err == nil {
		t.Fatal("expected second Seed to fail since buckets already exist")
	}
}

func TestGlobalKey(t *testing.T) {
	d := newTestDB(t)

	if _, err := d.GetGlobalKey(); !IsErrNotFound(err) {
		t.Fatalf("expected ErrNotFound before saving, got %v", err)
	}

	want := []byte("secret-key-bytes")
	if err := d.SaveGlobalKey(want); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetGlobalKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAccountKey(t *testing.T) {
	d := newTestDB(t)
	id := []byte("acc1")

	if _, err := d.GetAccountKey(id); !IsErrNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	jwk := testJWK(t)
	if err := d.SaveAccountKey(id, jwk); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetAccountKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Key, jwk.Key) {
		t.Error("retrieved key differs from saved key")
	}
}

func TestAccountLifecycle(t *testing.T) {
	d := newTestDB(t)
	id := []byte("acc1")

	if _, err := d.GetAccount(id); !IsErrNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	acc := DBAccount{ID: "acc1", Status: "valid", Contact: []string{"mailto:a@example.com"}, TermsOfServiceAgreed: true}
	jwk := testJWK(t)
	if err := d.CreateAccount(acc, jwk); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetAccount(id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, acc) {
		t.Errorf("got %+v, want %+v", got, acc)
	}

	// CreateAccount should also store the key
	if _, err := d.GetAccountKey(id); err != nil {
		t.Errorf("account key not stored: %v", err)
	}

	updated, err := d.UpdateAccount(id, func(a *DBAccount) error {
		a.Status = AccountStatusDeactivated
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != AccountStatusDeactivated {
		t.Errorf("returned account not updated: %+v", updated)
	}
	got, _ = d.GetAccount(id)
	if got.Status != AccountStatusDeactivated {
		t.Errorf("update not persisted: %+v", got)
	}

	if err := d.DeleteAccount(id); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetAccount(id); !IsErrNotFound(err) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}

	// The key must go too, otherwise the account's KID keeps authenticating requests
	if _, err := d.GetAccountKey(id); !IsErrNotFound(err) {
		t.Errorf("expected account key to be removed on delete, got %v", err)
	}
}

func TestUpdateCallbackErrorRollsBack(t *testing.T) {
	d := newTestDB(t)
	if err := d.CreateAccount(DBAccount{ID: "acc1", Status: "valid"}, testJWK(t)); err != nil {
		t.Fatal(err)
	}

	cbErr := errors.New("nope")
	_, err := d.UpdateAccount([]byte("acc1"), func(a *DBAccount) error {
		a.Status = "changed"
		return cbErr
	})
	if !errors.Is(err, cbErr) {
		t.Fatalf("expected callback error, got %v", err)
	}

	got, _ := d.GetAccount([]byte("acc1"))
	if got.Status != "valid" {
		t.Errorf("failed update was persisted: %+v", got)
	}
}

func TestUpdateMissingReturnsNotFound(t *testing.T) {
	d := newTestDB(t)

	if _, err := d.UpdateAccount([]byte("x"), func(*DBAccount) error { return nil }); !IsErrNotFound(err) {
		t.Errorf("account: got %v", err)
	}
	if _, err := d.UpdateOrder([]byte("x"), func(*DBOrder) error { return nil }); !IsErrNotFound(err) {
		t.Errorf("order: got %v", err)
	}
	if _, err := d.UpdateAuthz([]byte("x"), func(*DBAuthz) error { return nil }); !IsErrNotFound(err) {
		t.Errorf("authz: got %v", err)
	}
}

func TestOrderLifecycle(t *testing.T) {
	d := newTestDB(t)

	if _, err := d.GetOrder([]byte("o1")); !IsErrNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	order := DBOrder{
		ID:          "o1",
		AccountID:   "acc1",
		Status:      "pending",
		Expires:     1700000000,
		NotBefore:   ptr(int64(1)),
		Identifiers: []DBOrderIdentifier{{Type: "dns", Value: "a.example.com"}},
		AuthzIDs:    []string{"z1"},
	}
	if err := d.CreateOrder(order); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetOrder([]byte("o1"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, order) {
		t.Errorf("got %+v, want %+v", got, order)
	}

	updated, err := d.UpdateOrder([]byte("o1"), func(o *DBOrder) error {
		o.Status = "valid"
		o.CertificateID = "c1"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "valid" || updated.CertificateID != "c1" {
		t.Errorf("unexpected updated order: %+v", updated)
	}
}

func TestCertificate(t *testing.T) {
	d := newTestDB(t)

	if _, err := d.GetCertificate([]byte("c1")); !IsErrNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	cert := DBCertificate{ID: "c1", OrderID: "o1", AccountID: "acc1", Certificate: []byte("PEM DATA")}
	if err := d.CreateCertificate(cert); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCertificate([]byte("c1"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, cert) {
		t.Errorf("got %+v, want %+v", got, cert)
	}
}

func TestAuthzLifecycle(t *testing.T) {
	d := newTestDB(t)

	authz := DBAuthz{
		ID:                 "z1",
		OrderID:            "o1",
		AccountID:          "acc1",
		ExpireValidityTime: ptr(int64(1700000000)),
		Status:             "pending",
		Identifier:         DBOrderIdentifier{Type: "dns", Value: "a.example.com"},
		Challenges:         []DBAuthzChallenge{{ID: "ch1", Type: "http-01", Token: "tok", Status: "pending"}},
	}
	if err := d.CreateAuthz(authz); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetAuthz([]byte("z1"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, authz) {
		t.Errorf("got %+v, want %+v", got, authz)
	}

	updated, err := d.UpdateAuthz([]byte("z1"), func(a *DBAuthz) error {
		a.Challenges[0].Status = "valid"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Challenges[0].Status != "valid" {
		t.Errorf("unexpected: %+v", updated)
	}
}

func TestAuthzLocking(t *testing.T) {
	d := newTestDB(t)
	id := []byte("z1")

	if _, err := d.TryTakeAuthzLock(id); !IsErrNotFound(err) {
		t.Fatalf("expected ErrNotFound for missing authz, got %v", err)
	}

	if err := d.CreateAuthz(DBAuthz{ID: "z1"}); err != nil {
		t.Fatal(err)
	}

	ok, err := d.TryTakeAuthzLock(id)
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	ok, err = d.TryTakeAuthzLock(id)
	if err != nil || ok {
		t.Fatalf("second lock should fail: ok=%v err=%v", ok, err)
	}

	if err := d.UnlockAuthz(id); err != nil {
		t.Fatal(err)
	}
	ok, err = d.TryTakeAuthzLock(id)
	if err != nil || !ok {
		t.Fatalf("lock after unlock: ok=%v err=%v", ok, err)
	}
}

func TestAuthzLockIsExclusiveUnderConcurrency(t *testing.T) {
	d := newTestDB(t)
	if err := d.CreateAuthz(DBAuthz{ID: "z1"}); err != nil {
		t.Fatal(err)
	}

	const workers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := d.TryTakeAuthzLock([]byte("z1"))
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d goroutines acquired the lock, want exactly 1", winners)
	}
}

func TestIsAuthzLocked(t *testing.T) {
	d := newTestDB(t)
	b := d.(*BoltDB)

	if err := d.CreateAuthz(DBAuthz{ID: "z1"}); err != nil {
		t.Fatal(err)
	}
	if locked, err := b.IsAuthzLocked([]byte("z1")); err != nil || locked {
		t.Fatalf("locked=%v err=%v", locked, err)
	}
	d.TryTakeAuthzLock([]byte("z1"))
	if locked, err := b.IsAuthzLocked([]byte("z1")); err != nil || !locked {
		t.Fatalf("locked=%v err=%v", locked, err)
	}
	if _, err := b.IsAuthzLocked([]byte("missing")); !IsErrNotFound(err) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")

	d, err := NewBoltDb(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateOrder(DBOrder{ID: "o1", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	d.(*BoltDB).db.Close()

	d2, err := NewBoltDb(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.(*BoltDB).db.Close()

	got, err := d2.GetOrder([]byte("o1"))
	if err != nil || got.Status != "pending" {
		t.Errorf("got %+v, err %v", got, err)
	}
}

func TestIsErrNotFound(t *testing.T) {
	if !IsErrNotFound(ErrNotFound) {
		t.Error("ErrNotFound should match")
	}
	if !IsErrNotFound(errors.Join(errors.New("ctx"), ErrNotFound)) {
		t.Error("wrapped ErrNotFound should match")
	}
	if IsErrNotFound(errors.New("other")) || IsErrNotFound(nil) {
		t.Error("unrelated errors should not match")
	}
}
