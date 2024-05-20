package db

import "github.com/go-jose/go-jose/v3"

type DB interface {
	Seed() error

	SaveGlobalKey(privateKey []byte) error
	GetGlobalKey() ([]byte, error)

	SaveAccountKey(accountID []byte, key *jose.JSONWebKey) error
	GetAccountKey(accountID []byte) (*jose.JSONWebKey, error)

	GetAccount(accountID []byte) (*DBAccount, error)
	CreateAccount(acc DBAccount, key *jose.JSONWebKey) error
	UpdateAccount(accountID []byte, updateCallback func(*DBAccount) error) (*DBAccount, error)
	DeleteAccount(accountID []byte) error

	GetOrder(orderID []byte) (*DBOrder, error)
	CreateOrder(DBOrder) error
	UpdateOrder(orderID []byte, updateCallback func(*DBOrder) error) (*DBOrder, error)

	GetCertificate(certID []byte) (*DBCertificate, error)
	CreateCertificate(DBCertificate) error

	GetAuthz(authzID []byte) (*DBAuthz, error)
	CreateAuthz(DBAuthz) error
	UpdateAuthz(authzID []byte, updateCallback func(authzToUpdate *DBAuthz) error) (*DBAuthz, error)

	TryTakeAuthzLock(authzID []byte) (bool, error)
	UnlockAuthz(authzID []byte) error
}

type DBAccount struct {
	ID                   string   `json:"id"`
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Orders               []string `json:"orders"`
}

const AccountStatusDeactivated = "deactivated"

type DBOrder struct {
	ID        string `json:"id"`
	AccountID string `json:"account_id"`

	Status  string `json:"status"`
	Expires int64  `json:"expires"`

	NotBefore *int64 `json:"not_before,omitempty"`
	NotAfter  *int64 `json:"not_after,omitempty"`

	Identifiers   []DBOrderIdentifier `json:"identifiers"`
	CertificateID string              `json:"certificate_id"`

	ErrorID string `json:"error_id"`

	AuthzIDs []string `json:"authz_ids"`
}

type DBOrderIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DBCertificate struct {
	ID        string `json:"id"`
	OrderID   string `json:"order_id"`
	AccountID string `json:"account_id"`

	Certificate []byte `json:"certificate"`
}

type DBAuthz struct {
	ID                 string `json:"id"`
	OrderID            string `json:"order_id"`
	AccountID          string `json:"account_id"`
	ExpireValidityTime *int64 `json:"expires,omitempty"`

	Status     string            `json:"status"`
	Identifier DBOrderIdentifier `json:"identifier"`

	Challenges []DBAuthzChallenge `json:"challenges"`

	Locked bool `json:"_locked"`
}

type DBAuthzChallenge struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Token         string `json:"token"`
	Status        string `json:"status"`
	ValidatedTime *int64 `json:"validated_time"`
}
