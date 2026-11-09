package main

import (
	"strings"
	"testing"
)

func TestStrIsTruthy(t *testing.T) {
	for in, want := range map[string]bool{
		"true": true, "TRUE": true, "True": true, "yes": true, "YES": true, "1": true,
		" true ": true, "\tyes\n": true,
		"": false, "false": false, "no": false, "0": false, "2": false, "on": false, "y": false, "t": false, "truee": false,
	} {
		if got := strIsTruthy(in); got != want {
			t.Errorf("strIsTruthy(%q) = %v, want %v", in, got, want)
		}
	}
}

// clearEnv blanks every variable runServe reads so tests don't depend on the host environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		envPort, envUseTLS, envBaseURL, envHost, envStoragePath, envACMEPublicResolvers, envACMEDNSProvider,
		envACMEDirectory, envACMETOSAccept, envACMEEmail, envACMEKeyType, envACMEMetaTosURL, envACMEMetaCAAs, envACMEMetaWebsite,
	} {
		t.Setenv(k, "")
	}
}

// These cover only the validation that happens before server.Listen is reached.
func TestRunServeConfigValidation(t *testing.T) {
	t.Run("terms of service must be accepted", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envHost, "acmespider.example.com")

		err := runServe(nil)
		if err == nil || !strings.Contains(err.Error(), envACMETOSAccept) {
			t.Fatalf("got %v, want an error mentioning %s", err, envACMETOSAccept)
		}
	})

	t.Run("tos explicitly declined", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envHost, "acmespider.example.com")
		t.Setenv(envACMETOSAccept, "false")

		if err := runServe(nil); err == nil || !strings.Contains(err.Error(), envACMETOSAccept) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("hostname or base url required", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envACMETOSAccept, "true")

		err := runServe(nil)
		if err == nil || !strings.Contains(err.Error(), envBaseURL) || !strings.Contains(err.Error(), envHost) {
			t.Fatalf("got %v, want an error mentioning %s and %s", err, envBaseURL, envHost)
		}
	})

	t.Run("unparseable base url", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envACMETOSAccept, "true")
		t.Setenv(envBaseURL, "http://[::1")

		if err := runServe(nil); err == nil || !strings.Contains(err.Error(), "baseurl") {
			t.Fatalf("got %v", err)
		}
	})
}
