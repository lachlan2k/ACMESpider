//go:build !single_dns_provider

package server

import (
	"github.com/go-acme/lego/v4/challenge"
	dnsProviders "github.com/go-acme/lego/v4/providers/dns"
)

// newDNSProvider supports all lego DNS providers. This is the default build.
// The single_dns_provider tag replaces it with the one gendns writes.
func newDNSProvider(name string) (challenge.Provider, error) {
	return dnsProviders.NewDNSChallengeProviderByName(name)
}
