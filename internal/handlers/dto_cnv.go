package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

func time64ToString(t int64) string {
	return dtos.TimeMarshalDTO(time.Unix(t, 0))
}

func (h Handlers) dbOrderToDTO(order *db.DBOrder) dtos.OrderResponseDTO {
	identifiers := make([]dtos.OrderIdentifierDTO, len(order.Identifiers))
	for i, identifier := range order.Identifiers {
		identifiers[i] = dtos.OrderIdentifierDTO{
			Type:  identifier.Type,
			Value: identifier.Value,
		}
	}

	authzURLs := make([]string, len(order.AuthzIDs))
	for i, authzID := range order.AuthzIDs {
		authzURLs[i] = h.LinkCtrl.AuthzPath(authzID).Abs()
	}

	nbf := ""
	if order.NotBefore != nil {
		nbf = time64ToString(*order.NotBefore)
	}
	naft := ""
	if order.NotAfter != nil {
		naft = time64ToString(*order.NotAfter)
	}

	var errProblem *dtos.ProblemDTO = nil
	if order.ErrorID != "" {
		errProblem = &dtos.ProblemDTO{
			Type:       "urn:ietf:params:acme:error:serverInternal",
			HTTPStatus: http.StatusInternalServerError,
			Detail:     fmt.Sprintf("Error ID %s", order.ErrorID),
		}
	}

	return dtos.OrderResponseDTO{
		Status:            order.Status,
		Expires:           time64ToString(order.Expires),
		NotBefore:         nbf,
		NotAfter:          naft,
		Identifiers:       identifiers,
		AuthorizationURLs: authzURLs,
		Error:             errProblem,
		FinalizeURL:       h.LinkCtrl.FinalizeOrderPath(order.ID).Abs(),
		CertificateURL:    h.LinkCtrl.CertPath(order.CertificateID).Abs(),
	}
}

func (h Handlers) dbAccountToDTO(acc *db.DBAccount) dtos.AccountResponseDTO {
	return dtos.AccountResponseDTO{
		Status:               acc.Status,
		Contact:              acc.Contact,
		OrdersURL:            h.LinkCtrl.AccountOrdersPath(acc.ID).Abs(),
		TermsOfServiceAgreed: acc.TermsOfServiceAgreed,
	}
}

func (h Handlers) dbIdentifierToDTO(id db.DBOrderIdentifier) dtos.AuthzIdentifierDTO {
	return dtos.AuthzIdentifierDTO{
		Type:  id.Type,
		Value: id.Value,
	}
}

func (h Handlers) dbAuthzToDTO(authz *db.DBAuthz) dtos.AuthzDTO {
	expiresTime := ""
	if authz.ExpireValidityTime != nil {
		expiresTime = time64ToString(*authz.ExpireValidityTime)
	}

	dtoChallenges := make([]dtos.AuthzChallengeDTO, len(authz.Challenges))
	for i, chall := range authz.Challenges {
		valTime := ""
		if chall.ValidatedTime != nil {
			valTime = time64ToString(*chall.ValidatedTime)
		}

		dtoChallenges[i] = dtos.AuthzChallengeDTO{
			URL:           h.LinkCtrl.ChallengePath(chall.ID).Abs(),
			Type:          chall.Type,
			Status:        chall.Status,
			Token:         chall.Token,
			ValidatedTime: valTime,
		}
	}

	return dtos.AuthzDTO{
		Status:     authz.Status,
		Expires:    expiresTime,
		Identifier: h.dbIdentifierToDTO(authz.Identifier),
		Challenges: dtoChallenges,
	}
}

func (h Handlers) dbChallengeToDTO(chall *db.DBAuthzChallenge) dtos.AuthzChallengeDTO {
	valTime := ""
	if chall.ValidatedTime != nil {
		valTime = time64ToString(*chall.ValidatedTime)
	}

	return dtos.AuthzChallengeDTO{
		URL:           h.LinkCtrl.ChallengePath(chall.ID).Abs(),
		Type:          chall.Type,
		Status:        chall.Status,
		Token:         chall.Token,
		ValidatedTime: valTime,
	}
}
