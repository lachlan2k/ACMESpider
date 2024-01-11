package dtos

const (
	OrderStatusPending = "pending"
	OrderStatusValid   = "valid"
	OrderStatusReady   = "ready"
)

type OrderCreateRequestDTO struct {
	Identifiers []OrderIdentifierDTO `json:"identifiers"`
	NotBefore   string               `json:"notBefore"`
	NotAfter    string               `json:"notAfter"`
}

type OrderFinalizeRequestDTO struct {
	CSRB64 string `json:"csr"`
}

type OrdersListResponseDTO struct {
	Orders []string `json:"orders"`
}

type OrderResponseDTO struct {
	Status  string `json:"status"`
	Expires string `json:"expires"`

	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`

	Identifiers []OrderIdentifierDTO `json:"identifiers"`

	AuthorizationURLs []string `json:"authorizations"`
	FinalizeURL       string   `json:"finalize"`
	CertificateURL    string   `json:"certificate,omitempty"`
}

type OrderIdentifierDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
