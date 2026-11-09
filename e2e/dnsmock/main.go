// dnsmock is a minimal authoritative DNS server for the end-to-end tests. It serves a single zone with
// SOA, NS and A records for itself (and for the test hosts, via docker's DNS), plus TXT records that are managed over a tiny HTTP API:
//
//	POST /set-txt    {"host": "_acme-challenge.example.test.", "value": "..."}   adds a TXT value
//	POST /clear-txt  {"host": "_acme-challenge.example.test."}                   removes the name's TXT values
//
// pebble-challtestsrv has the same API but answers SOA queries with NOTIMP, and lego (which ACMESpider uses
// upstream) needs a real SOA/NS answer to work out which zone a challenge record belongs to.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type server struct {
	zone string // fqdn, lower case, e.g. "test."
	ns   string // name of our own nameserver, ns.<zone>
	ip   net.IP

	mu  sync.RWMutex
	txt map[string][]string
}

func (s *server) soa() dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: s.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1},
		Ns:      s.ns,
		Mbox:    "hostmaster." + s.zone,
		Serial:  1,
		Refresh: 60, Retry: 60, Expire: 60, Minttl: 1,
	}
}

func (s *server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(dns.Fqdn(q.Name))

	if !dns.IsSubDomain(s.zone, name) {
		m.Rcode = dns.RcodeRefused
		m.Authoritative = false
		w.WriteMsg(m)
		return
	}

	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: 1}
	}

	switch q.Qtype {
	case dns.TypeTXT:
		s.mu.RLock()
		for _, v := range s.txt[name] {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: []string{v}})
		}
		s.mu.RUnlock()
	case dns.TypeSOA:
		if name == s.zone {
			m.Answer = append(m.Answer, s.soa())
		}
	case dns.TypeNS:
		if name == s.zone {
			m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(dns.TypeNS), Ns: s.ns})
		}
	case dns.TypeA:
		if name == s.ns {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: s.ip})
			break
		}
		// Everything else is a host in the test network (the ACME clients, which have docker network aliases
		// like certbot.test). pebble resolves challenge targets through us, so hand out what docker's DNS says.
		ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", strings.TrimSuffix(name, "."))
		if err != nil {
			m.Rcode = dns.RcodeNameError
			break
		}
		for _, ip := range ips {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: ip})
		}
	}

	// Anything without an answer is NODATA, with the SOA in the authority section as a real server would send
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, s.soa())
	}
	w.WriteMsg(m)
}

func (s *server) handleTXT(set bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Host, Value string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Host == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		host := strings.ToLower(dns.Fqdn(body.Host))

		s.mu.Lock()
		defer s.mu.Unlock()
		if set {
			s.txt[host] = append(s.txt[host], body.Value)
			log.Printf("set-txt %s", host)
		} else {
			delete(s.txt, host)
			log.Printf("clear-txt %s", host)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func ownIP() net.IP {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.To4()
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

func main() {
	zone := strings.ToLower(dns.Fqdn(getenv("DNSMOCK_ZONE", "test.")))
	s := &server{zone: zone, ns: "ns." + zone, ip: ownIP(), txt: map[string][]string{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/set-txt", s.handleTXT(true))
	mux.HandleFunc("/clear-txt", s.handleTXT(false))
	go func() { log.Fatal(http.ListenAndServe(getenv("DNSMOCK_MGMT", ":8055"), mux)) }()

	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: ":53", Net: network, Handler: s}
		go func() { log.Fatal(srv.ListenAndServe()) }()
	}
	log.Printf("serving zone %s (ns %s -> %s)", s.zone, s.ns, s.ip)
	select {}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
