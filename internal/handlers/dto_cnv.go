package handlers

import (
	"time"

	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/dtos"
)

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
		Expires:           time.Unix(order.Expires, 0).Format(time.RFC3339),
		NotBefore:         time.Unix(order.NotBefore, 0).Format(time.RFC3339),
		NotAfter:          time.Unix(order.NotAfter, 0).Format(time.RFC3339),
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
