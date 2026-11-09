package acme_controller

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
	"github.com/sirupsen/logrus"
)

const HTTP01ChallengeType = "http-01"

// Key authorizations are ~100 bytes; anything much bigger isn't one
const maxKeyAuthorizationSize = 1024

var http01Client = &http.Client{Timeout: 10 * time.Second}

var errChallengeInProgress = errors.New("challenge validation is already in progress")

func fetchKeyAuthorization(client *http.Client, challURL string) (string, error) {
	resp, err := client.Get(challURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyAuthorizationSize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxKeyAuthorizationSize {
		return "", fmt.Errorf("response was larger than %d bytes", maxKeyAuthorizationSize)
	}
	return string(body), nil
}

func keyAuthorizationMatches(body string, token string, thumbprint []byte) bool {
	// Check the server's response against token.base64url(thumbprint)

	// RFC 8555 8.3 says to ignore trailing whitespace
	gotToken, gotThumbprint, ok := strings.Cut(strings.TrimRight(body, " \t\r\n"), ".")
	if !ok || gotToken != token {
		return false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(gotThumbprint)
	if err != nil {
		return false
	}
	return bytes.Equal(thumbprint, decoded)
}

func (ac ACMEController) startHTTP01Challenge(order *db.DBOrder, authz *db.DBAuthz, challengeIndex int) error {
	errChan := make(chan error, 1)
	go func() {
		errChan <- ac.doHTTP01ChallengeVerifyLoop(order, authz, challengeIndex)
	}()

	select {
	case err := <-errChan:
		return err
	case <-time.After(5 * time.Second):
		return nil
	}
}

func (ac ACMEController) doHTTP01ChallengeVerifyLoop(order *db.DBOrder, authz *db.DBAuthz, challengeIndex int) error {
	lockSuccess, err := ac.db.TryTakeAuthzLock([]byte(authz.ID))
	if err != nil {
		return err
	}
	if !lockSuccess {
		return fmt.Errorf("authz %s: %w", authz.ID, errChallengeInProgress)
	}
	defer ac.db.UnlockAuthz([]byte(authz.ID))
	defer ac.recomputeOrderStatus([]byte(order.ID))

	if challengeIndex >= len(authz.Challenges) {
		return fmt.Errorf("challenge index is invalid")
	}
	challenge := authz.Challenges[challengeIndex]
	if challenge.Type != HTTP01ChallengeType {
		return fmt.Errorf("challenge type is %s not %s", challenge.Type, HTTP01ChallengeType)
	}
	if challenge.Status != dtos.ChallengeStatusPending {
		return fmt.Errorf("challenge status is %s not %s", challenge.Status, dtos.ChallengeStatusPending)
	}

	accKey, err := ac.db.GetAccountKey([]byte(order.AccountID))
	if err != nil {
		return err
	}

	computedThumbprint, err := accKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}

	challURL := url.URL{
		Scheme: "http",
		Host:   authz.Identifier.Value,
		Path:   "/.well-known/acme-challenge/" + challenge.Token,
	}

	attempt := func() bool {
		body, err := fetchKeyAuthorization(http01Client, challURL.String())
		if err != nil {
			logrus.WithError(err).WithField("url", challURL.String()).Debug("failed to fetch key authorization when completing challenge")
			return false
		}
		return keyAuthorizationMatches(body, challenge.Token, computedThumbprint)
	}

	_, err = ac.db.UpdateAuthz([]byte(authz.ID), func(authzToUpdate *db.DBAuthz) error {
		authzToUpdate.Challenges[challengeIndex].Status = dtos.ChallengeStatusProcessing
		return nil
	})

	// Tries once a second for a minute
	endTime := time.Now().Add(time.Minute)
	for time.Now().Before(endTime) {
		result := attempt()
		if result {
			_, err = ac.db.UpdateAuthz([]byte(authz.ID), func(authzToUpdate *db.DBAuthz) error {
				authzToUpdate.Status = dtos.AuthzStatusValid
				authzToUpdate.Challenges[challengeIndex].Status = dtos.ChallengeStatusValid

				valTime := timeMarshalDB(time.Now())
				authzToUpdate.Challenges[challengeIndex].ValidatedTime = &valTime
				return nil
			})
			return err
		}

		time.Sleep(time.Second)
	}

	_, err = ac.db.UpdateAuthz([]byte(authz.ID), func(authzToUpdate *db.DBAuthz) error {
		authzToUpdate.Status = dtos.AuthzStatusInvalid
		authzToUpdate.Challenges[challengeIndex].Status = dtos.ChallengeStatusInvalid
		return nil
	})
	return err
}
