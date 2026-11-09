package acme_controller

import (
	"strings"
	"testing"
)

func TestIsDNSName(t *testing.T) {
	label63 := strings.Repeat("a", 63)

	tests := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"a.b.c.d.example.com", true},
		{"EXAMPLE.com", true},
		{"localhost", true},
		{"xn--bcher-kva.example", true},
		{"with-hyphen.example.com", true},
		{"_acme-challenge.example.com", true},
		{"example.com.", true}, // trailing dot
		{"123.example.com", true},
		{label63 + ".com", true},

		{"", false},
		{".", false},
		{".example.com", false},
		{"example..com", false},
		{"-leading.example.com", false},
		{"exa mple.com", false},
		{"example.com/path", false},
		{"example.com:443", false},
		{"https://example.com", false},
		{"user@example.com", false},
		{"*.example.com", false},
		{"exämple.com", false},
		{"example.com\n", false},
		{label63 + "a.com", false},                 // 64-char label
		{strings.Repeat("a.", 256) + "com", false}, // 259 chars without dots; the limit counts non-dot characters

		// IPs are not DNS names
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"::1", false},
		{"2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := IsDNSName(tt.in); got != tt.want {
				t.Errorf("IsDNSName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
