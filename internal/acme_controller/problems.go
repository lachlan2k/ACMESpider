package acme_controller

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

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
	Type        string                       `json:"type,omitempty"`
	Detail      string                       `json:"detail,omitempty"`
	HTTPStatus  int                          `json:"status,omitempty"`
	Identifier  *IdentifierForProblemDetails `json:"identifier,omitempty"`
	Subproblems []ProblemDetails             `json:"subproblems,omitempty"`
	wrapped     error
	wrappedId   string
}

type IdentifierForProblemDetails struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (pd ProblemDetails) Error() string {
	return fmt.Sprintf("%s :: %s", pd.Type, pd.Detail)
}

func (pd ProblemDetails) Unwrap() error {
	return pd.wrapped
}

func (pd ProblemDetails) ID() string {
	return pd.wrappedId
}

func InternalErrorProblem(wrapped error) *ProblemDetails {
	id := uuid.NewString()

	return &ProblemDetails{
		Type:       serverInternalErr,
		Detail:     fmt.Sprintf("Error ID %s", id),
		HTTPStatus: http.StatusInternalServerError,
		wrapped:    wrapped,
		wrappedId:  id,
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

func RejectedIdentifierProblem(ident IdentifierForProblemDetails, detail string) *ProblemDetails {
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
