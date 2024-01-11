package dtos

const (
	AccountStatusDeactivated = "deactivated"
	AccountStatusValid       = "valid"
	AccountStatusRevoked     = "revoked"
)

type AccountRequestDTO struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

type AccountResponseDTO struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	OrdersURL            string   `json:"orders"`
}
