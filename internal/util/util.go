package util

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"regexp"
	"strings"
)

func GenerateID() (string, error) {
	buff := make([]byte, 16)
	_, err := rand.Read(buff)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buff), nil
}

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
