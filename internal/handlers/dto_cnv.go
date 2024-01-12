package handlers

import (
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

	return dtos.OrderResponseDTO{
		Status:            order.Status,
		Expires:           time64ToString(order.Expires),
		NotBefore:         time64ToString(order.NotBefore),
		NotAfter:          time64ToString(order.NotAfter),
		Identifiers:       identifiers,
		AuthorizationURLs: authzURLs,
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
