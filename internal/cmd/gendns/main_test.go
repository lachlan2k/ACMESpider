package main

import "testing"

func TestPkgOf(t *testing.T) {
	tests := []struct {
		name    string
		wantPkg string
		wantErr bool
	}{
		{name: "ionos", wantPkg: "ionos"},
		{name: "acme-dns", wantPkg: "acmedns"},
		{name: "acmedns", wantPkg: "acmedns"},
		{name: "fastdns", wantPkg: "edgedns"},
		{name: "edgedns", wantPkg: "edgedns"},
		{name: "linodev4", wantPkg: "linode"},
		{name: "domainnameshop", wantPkg: "domeneshop"},
		{name: "dnsupdate", wantPkg: "rfc2136"},
		{name: "webnamesru", wantPkg: "webnames"},
		{name: "Route53", wantErr: true},
		{name: "a/b", wantErr: true},
		{name: "io-nos", wantErr: true},
		{name: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := pkgOf(tt.name)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if pkg != tt.wantPkg {
				t.Errorf("got %q, want %q", pkg, tt.wantPkg)
			}
		})
	}
}
