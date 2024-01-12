package acme_controller

import (
	"net"
	"regexp"
	"strings"
)

var dnsNamePattern = regexp.MustCompile(`^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\._]?$`)

func IsDNSName(str string) bool {
	if str == "" || len(strings.Replace(str, ".", "", -1)) > 255 {
		// constraints already violated
		return false
	}
	return !IsIP(str) && dnsNamePattern.MatchString(str)
}

func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}
