package acme_controller

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

func (ac ACMEController) splitChallengeID(challID []byte) (authzID []byte, challengeIndex int, err error) {
	// Challenge ID is just the Authz ID followed by hex-encoded index of the challenge
	if len(challID) < 3 {
		err = MalformedProblem("Challenge ID too short")
		return
	}

	authzID = challID[:len(challID)-2]
	encodedChallengeIndex := challID[len(challID)-2:]

	challengeIndex64, err := strconv.ParseInt(string(encodedChallengeIndex), 16, 32)
	if err != nil {
		err = MalformedProblem("Invalid challenge ID")
		return
	}

	challengeIndex = int(challengeIndex64)
	return
}

func (ac ACMEController) InitiateChallenge(challID []byte, requesterAccountID []byte) error {
	authzID, challengeIndex, err := ac.splitChallengeID(challID)
	if err != nil {
		return err
	}

	authz, err := ac.db.GetAuthz(authzID)
	if err != nil {
		return UnauthorizedProblem("")
	}

	if !bytes.Equal(requesterAccountID, []byte(authz.AccountID)) {
		return UnauthorizedProblem("")
	}

	if challengeIndex >= len(authz.Challenges) {
		return NotFoundProblem("Unknown challenge ID")
	}

	order, err := ac.db.GetOrder([]byte(authz.OrderID))
	if err != nil {
		return InternalErrorProblem(fmt.Errorf("failed to get order when initiating challenge: %v", err))
	}

	return ac.doHTTP01ChallengeVerifyLoop(order, authz, challengeIndex)
}

func (ac ACMEController) recomputeOrderStatus(orderID []byte) error {
	order, err := ac.db.GetOrder(orderID)
	if err != nil {
		return err
	}

	// As of now, this function is only responsible for state changes from pending -> other things
	if order.Status != dtos.OrderStatusPending {
		return nil
	}

	// Check if its expired
	if timeUnmarshalDB(order.Expires).Before(time.Now()) {
		_, err := ac.db.UpdateOrder(orderID, func(orderToUpdate *db.DBOrder) error {
			orderToUpdate.Status = dtos.OrderStatusExpired
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to update order to expired: %v", err)
		}
	}

	allValid := true
	for _, authzID := range order.AuthzIDs {
		authz, err := ac.db.GetAuthz([]byte(authzID))
		if err != nil {
			return err
		}
		if authz.Status != dtos.AuthzStatusValid {
			allValid = false
			break
		}
	}

	if allValid {
		ac.db.UpdateOrder(orderID, func(orderToUpdate *db.DBOrder) error {
			orderToUpdate.Status = "ready"
			return nil
		})
	}

	return nil
}
