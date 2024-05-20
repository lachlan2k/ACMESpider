package dtos

const (
	OrderStatusPending    = "pending"
	OrderStatusProcessing = "processing"
	OrderStatusValid      = "valid"
	OrderStatusInvalid    = "invalid"
	OrderStatusReady      = "ready"
	OrderStatusExpired    = "expired"
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

type ProblemDTO struct {
	Type        string                   `json:"type,omitempty"`
	Detail      string                   `json:"detail,omitempty"`
	HTTPStatus  int                      `json:"status,omitempty"`
	Identifier  *IdentifierForProblemDTO `json:"identifier,omitempty"`
	Subproblems []ProblemDTO             `json:"subproblems,omitempty"`
}

type IdentifierForProblemDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OrderResponseDTO struct {
	Status  string `json:"status"`
	Expires string `json:"expires"`

	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`

	Identifiers []OrderIdentifierDTO `json:"identifiers"`

	Error *ProblemDTO `json:"error,omitempty"`

	AuthorizationURLs []string `json:"authorizations"`
	FinalizeURL       string   `json:"finalize"`
	CertificateURL    string   `json:"certificate,omitempty"`
}

type OrderIdentifierDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
