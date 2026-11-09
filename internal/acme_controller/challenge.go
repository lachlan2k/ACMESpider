package acme_controller

import (
	"bytes"
	"errors"
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

	// ParseUint rather than ParseInt: a signed index like "-1" would pass the upper bounds check
	// later on and then panic when indexing the challenges slice
	challengeIndex64, err := strconv.ParseUint(string(encodedChallengeIndex), 16, 8)
	if err != nil {
		err = MalformedProblem("Invalid challenge ID")
		return
	}

	challengeIndex = int(challengeIndex64)
	return
}

func (ac ACMEController) AuthzIDFromChallengeID(challID []byte) ([]byte, error) {
	authzID, _, err := ac.splitChallengeID(challID)
	return authzID, err
}

func (ac ACMEController) InitiateChallenge(challID []byte, requesterAccountID []byte) (*db.DBAuthzChallenge, error) {
	authzID, challengeIndex, err := ac.splitChallengeID(challID)
	if err != nil {
		return nil, err
	}

	authz, err := ac.db.GetAuthz(authzID)
	if err != nil {
		return nil, UnauthorizedProblem("")
	}

	if !bytes.Equal(requesterAccountID, []byte(authz.AccountID)) {
		return nil, UnauthorizedProblem("")
	}

	if challengeIndex >= len(authz.Challenges) {
		return nil, NotFoundProblem("Unknown challenge ID")
	}

	// RFC 8555 8.2 lets clients re-send their response to ask for a retry, so re-sending isn't an error while
	// the challenge is processing. The RFC doesn't say what to do once it's valid or invalid; we report the
	// challenge as it stands rather than failing the request.
	if existing := authz.Challenges[challengeIndex]; existing.Status != dtos.ChallengeStatusPending {
		return &existing, nil
	}

	order, err := ac.db.GetOrder([]byte(authz.OrderID))
	if err != nil {
		return nil, InternalErrorProblem(fmt.Errorf("failed to get order when initiating challenge: %v", err))
	}

	err = ac.startHTTP01Challenge(order, authz, challengeIndex)
	if err != nil && !errors.Is(err, errChallengeInProgress) {
		var pd *ProblemDetails
		if errors.As(err, &pd) {
			return nil, pd
		}
		return nil, InternalErrorProblem(err)
	}

	latestAuthz, err := ac.db.GetAuthz(authzID)
	if err != nil {
		return nil, InternalErrorProblem(fmt.Errorf("failed to get latest authz: %v", err))
	}

	if challengeIndex >= len(latestAuthz.Challenges) {
		return nil, InternalErrorProblem(fmt.Errorf("challenge index on latestAuthz was unexpectedlty out of bounds"))
	}
	chall := latestAuthz.Challenges[challengeIndex]
	return &chall, nil
}

func (ac ACMEController) recomputeOrderStatus(orderID []byte) error {
	order, err := ac.db.GetOrder(orderID)
	if err != nil {
		return err
	}

	// As of now, this function is only responsible for state changes from pending/ready -> other things
	// TODO: support expiring authzs?
	// TODO: read all state transitions in the RFC
	if order.Status != dtos.OrderStatusPending && order.Status != dtos.OrderStatusReady {
		return nil
	}

	// Check if its expired
	if timeUnmarshalDB(order.Expires).Before(time.Now()) {
		_, err := ac.db.UpdateOrder(orderID, func(orderToUpdate *db.DBOrder) error {
			// RFC 8555 7.1.6: an order that expires moves to invalid
			orderToUpdate.Status = dtos.OrderStatusInvalid
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to update order to expired: %v", err)
		}
		// Bail. Don't check the authz's of an expired order
		return nil
	}

	// Stop here if the order is already Ready
	if order.Status != dtos.OrderStatusPending {
		return nil
	}

	allValid := true
	for _, authzID := range order.AuthzIDs {
		authz, err := ac.db.GetAuthz([]byte(authzID))
		if err != nil {
			return err
		}

		switch authz.Status {
		case dtos.AuthzStatusValid:
			// do nothing :)
		case dtos.AuthzStatusInvalid, dtos.AuthzStatusExpired, dtos.AuthzStatusRevoked, dtos.AuthzStatusDeactivated:
			// RFC 8555 7.1.6: an authz in a final state other than valid makes the order invalid
			_, err := ac.db.UpdateOrder(orderID, func(orderToUpdate *db.DBOrder) error {
				orderToUpdate.Status = dtos.OrderStatusInvalid
				return nil
			})
			return err
		default:
			allValid = false
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
