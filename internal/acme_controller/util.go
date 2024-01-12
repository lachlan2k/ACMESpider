package acme_controller

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateID() (string, error) {
	buff := make([]byte, 16)
	_, err := rand.Read(buff)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buff), nil
}

func GenerateChallengeToken() (string, error) {
	buff := make([]byte, 32)
	_, err := rand.Read(buff)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buff), nil
}
