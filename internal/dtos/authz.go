package dtos

const (
	AuthzStatusPending     = "pending"
	AuthzStatusValid       = "valid"
	AuthzStatusInvalid     = "invalid"
	AuthzStatusDeactivated = "deactivated"
	AuthzStatusExpired     = "expired"
	AuthzStatusRevoked     = "revoked"

	ChallengeStatusPending    = "pending"
	ChallengeStatusProcessing = "processing"
	ChallengeStatusValid      = "valid"
	ChallengeStatusInvalid    = "invalid"
)

type AuthzCreateRequestDTO struct {
	Identifier AuthzIdentifierDTO `json:"identifier"`
}

type AuthzDTO struct {
	Status     string              `json:"status"`
	Expires    string              `json:"expires"`
	Identifier AuthzIdentifierDTO  `json:"identifier"`
	Challenges []AuthzChallengeDTO `json:"challenges"`
	Wildcard   bool                `json:"wildcard"`
}

type AuthzIdentifierDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AuthzChallengeDTO struct {
	URL       string `json:"url"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	Token     string `json:"token"`
	Validated string `json:"validated"`
}
