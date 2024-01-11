package nonce

import (
	"regexp"
	"testing"
	"time"
)

func TestCreatingInMemController(t *testing.T) {
	ctrl := NewInMemCtrl()
	if ctrl == nil {
		t.Fatal("NewInMemCtrl returned nil")
	}
}

func TestNonceIsValid(t *testing.T) {
	ctrl := NewInMemCtrl()

	want := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)

	// Make a bunch so we can ensure charset is consistently fine
	for i := 0; i < 10000; i++ {
		nonce, err := ctrl.Gen()
		if err != nil {
			t.Fatalf("error when generating nonce: %v", err)
		}
		if len(nonce) < 16 {
			t.Fatalf("nonce is too short (%d chars), min is 16", len(nonce))
		}

		if !want.Match([]byte(nonce)) {
			t.Fatalf("nonce did not match regex %s, nonce was %s", want.String(), nonce)
		}
	}

}

func TestNonceValidation(t *testing.T) {
	ctrl := NewInMemCtrl()

	nonce, _ := ctrl.Gen()
	valid, err := ctrl.ValidateAndConsume(nonce)
	if err != nil {
		t.Fatalf("failed to validate nonce %s: %v", nonce, err)
	}

	if !valid {
		t.Fatalf("nonce %s was considered invalid, but it should have been valid (first use)", nonce)
	}

	valid, err = ctrl.ValidateAndConsume(nonce)
	if valid {
		t.Fatalf("nonce %s was allowed to be valid twice, (err %v)", nonce, err)
	}

	for i := 0; i < 10000; i++ {
		ctrl.Gen()
	}

	valid, err = ctrl.ValidateAndConsume(nonce)
	if valid {
		t.Fatalf("nonce %s was allowed to be valid twice after generating many nonces, (err %v)", nonce, err)
	}

	for i := 0; i < 65535*2; i++ {
		ctrl.Gen()
	}

	valid, err = ctrl.ValidateAndConsume(nonce)
	if valid {
		t.Fatalf("nonce %s was allowed to be valid twice after generating many nonces, (err %v)", nonce, err)
	}

	nonce, _ = ctrl.Gen()
	for i := 0; i < 65535*2; i++ {
		ctrl.Gen()
	}

	valid, _ = ctrl.ValidateAndConsume(nonce)
	if valid {
		t.Fatalf("nonce %s was considred valid, despite the fact the circular buffer should have rolled over (err %v)", nonce, err)
	}

	memCtrl, ok := ctrl.(*InMemController)
	if ok {
		memCtrl.maxLifetime = time.Second
		nonce, _ = ctrl.Gen()
		time.Sleep(time.Second)
		valid, _ = ctrl.ValidateAndConsume(nonce)
		if valid {
			t.Fatalf("nonce %s was considred valid, despite the fact time should have expired", nonce)
		}
	}
}
