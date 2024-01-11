package acme_controller

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
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

type ACMEController struct {
	DB db.DB
}

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

func (ac ACMEController) StartHTTP01Challenge(order *db.DBOrder, authz *db.DBAuthz) error {
	errChan := make(chan error, 1)
	go func() {
		errChan <- ac.DoHTTP01ChallengeVerifyLoop(order, authz)
	}()

	select {
	case err := <-errChan:
		return err
	case <-time.After(time.Second):
		return nil
	}
}

func (ac ACMEController) DoHTTP01ChallengeVerifyLoop(order *db.DBOrder, authz *db.DBAuthz) error {
	lockSuccess, err := ac.DB.TryTakeAuthzLock([]byte(authz.ID))
	if err != nil {
		return err
	}
	if !lockSuccess {
		return fmt.Errorf("authz %s is locked - challenge in progress", authz.ID)
	}
	defer ac.DB.UnlockAuthz([]byte(authz.ID))

	accKey, err := ac.DB.GetAccountKey([]byte(order.AccountID))
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
		Path:   "/.well-known/acme-challenge/" + authz.ChallengeToken,
	}

	attempt := func() bool {
		resp, err := http.Get(challURL.String())
		if err != nil {
			logrus.WithError(err).WithField("url", challURL.String()).Debug("failed to make request when completing challenge")
			return false
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			logrus.WithError(err).WithField("url", challURL.String()).Debug("failed to ready body when completing challenge")
			return false
		}

		token, thumbprint, cutOk := strings.Cut(string(respBody), ".")
		if !cutOk {
			return false
		}

		if token != authz.ChallengeToken {
			return false
		}

		decodedThumbprint, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(thumbprint, " "))
		if err != nil {
			return false
		}

		return bytes.Equal(computedThumbprint, decodedThumbprint)
	}

	// Tries once a second for a minute
	endTime := time.Now().Add(time.Minute)
	for time.Now().Before(endTime) {
		result := attempt()
		if result {
			_, err = ac.DB.UpdateAuthz([]byte(authz.ID), func(authzToUpdate *db.DBAuthz) error {
				authzToUpdate.Status = dtos.AuthzStatusValid
				return nil
			})
			return err
		}

		time.Sleep(time.Second)
	}

	_, err = ac.DB.UpdateAuthz([]byte(authz.ID), func(authzToUpdate *db.DBAuthz) error {
		authzToUpdate.Status = dtos.AuthzStatusInvalid
		return nil
	})
	return err
}
