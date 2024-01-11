package handlers

import (
	"fmt"
	"net/http"
)

// acme.Resource values identify different types of ACME resources
type Resource string

const (
	StatusPending     = "pending"
	StatusInvalid     = "invalid"
	StatusValid       = "valid"
	StatusExpired     = "expired"
	StatusProcessing  = "processing"
	StatusReady       = "ready"
	StatusDeactivated = "deactivated"

	IdentifierDNS = "dns"
	IdentifierIP  = "ip"

	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
	ChallengeDNS01     = "dns-01"

	HTTP01BaseURL = ".well-known/acme-challenge/"

	ACMETLS1Protocol = "acme-tls/1"
)

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (ident Identifier) Equals(other Identifier) bool {
	return ident.Type == other.Type && ident.Value == other.Value
}

type JSONSigned struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Sig       string `json:"signature"`
}

type Account struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders,omitempty"`

	ExternalAccountBinding *JSONSigned `json:"externalAccountBinding,omitempty"`
}

// An Order is created to request issuance for a CSR
type Order struct {
	Status         string          `json:"status"`
	Error          *ProblemDetails `json:"error,omitempty"`
	Expires        string          `json:"expires"`
	Identifiers    []Identifier    `json:"identifiers,omitempty"`
	Finalize       string          `json:"finalize"`
	NotBefore      string          `json:"notBefore,omitempty"`
	NotAfter       string          `json:"notAfter,omitempty"`
	Authorizations []string        `json:"authorizations"`
	Certificate    string          `json:"certificate,omitempty"`
}

// An Authorization is created for each identifier in an order
type Authorization struct {
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Expires    string      `json:"expires"`
	// Wildcard is a Let's Encrypt specific Authorization field that indicates the
	// authorization was created as a result of an order containing a name with
	// a `*.`wildcard prefix. This will help convey to users that an
	// Authorization with the identifier `example.com` and one DNS-01 challenge
	// corresponds to a name `*.example.com` from an associated order.
	Wildcard bool `json:"wildcard,omitempty"`
}

// A Challenge is used to validate an Authorization
type Challenge struct {
	Type      string          `json:"type"`
	URL       string          `json:"url"`
	Token     string          `json:"token"`
	Status    string          `json:"status"`
	Validated string          `json:"validated,omitempty"`
	Error     *ProblemDetails `json:"error,omitempty"`
}

const (
	errNS                  = "urn:ietf:params:acme:error:"
	serverInternalErr      = errNS + "serverInternal"
	malformedErr           = errNS + "malformed"
	badNonceErr            = errNS + "badNonce"
	badCSRErr              = errNS + "badCSR"
	agreementReqErr        = errNS + "agreementRequired"
	externalAccountReqErr  = errNS + "externalAccountRequired"
	connectionErr          = errNS + "connection"
	unauthorizedErr        = errNS + "unauthorized"
	invalidContactErr      = errNS + "invalidContact"
	unsupportedContactErr  = errNS + "unsupportedContact"
	accountDoesNotExistErr = errNS + "accountDoesNotExist"
	badRevocationReasonErr = errNS + "badRevocationReason"
	alreadyRevokedErr      = errNS + "alreadyRevoked"
	orderNotReadyErr       = errNS + "orderNotReady"
	badPublicKeyErr        = errNS + "badPublicKey"
	rejectedIdentifierErr  = errNS + "rejectedIdentifier"
)

type ProblemDetails struct {
	Type        string           `json:"type,omitempty"`
	Detail      string           `json:"detail,omitempty"`
	HTTPStatus  int              `json:"status,omitempty"`
	Identifier  *Identifier      `json:"identifier,omitempty"`
	Subproblems []ProblemDetails `json:"subproblems,omitempty"`
}

func (pd *ProblemDetails) Error() string {
	return fmt.Sprintf("%s :: %s", pd.Type, pd.Detail)
}

func InternalErrorProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       serverInternalErr,
		Detail:     detail,
		HTTPStatus: http.StatusInternalServerError,
	}
}

func MalformedProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NotFoundProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusNotFound,
	}
}

func MethodNotAllowed() *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     "Method not allowed",
		HTTPStatus: http.StatusMethodNotAllowed,
	}
}

func BadNonceProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badNonceErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func BadCSRProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badCSRErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func Conflict(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusConflict,
	}
}

func AgreementRequiredProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       agreementReqErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

func ExternalAccountRequiredProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       externalAccountReqErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

func ConnectionProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       connectionErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func UnauthorizedProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       unauthorizedErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

func InvalidContactProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       invalidContactErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func UnsupportedContactProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       unsupportedContactErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func AccountDoesNotExistProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       accountDoesNotExistErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func UnsupportedMediaTypeProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusUnsupportedMediaType,
	}
}

func BadRevocationReasonProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badRevocationReasonErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func AlreadyRevokedProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       alreadyRevokedErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func OrderNotReadyProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       orderNotReadyErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

func BadPublicKeyProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badPublicKeyErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func RejectedIdentifierProblem(ident Identifier, detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       rejectedIdentifierErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
		Subproblems: []ProblemDetails{
			{
				Type:       rejectedIdentifierErr,
				Identifier: &ident,
				Detail:     fmt.Sprintf("%s is a forbidden domain", ident.Value),
			},
		},
	}
}
