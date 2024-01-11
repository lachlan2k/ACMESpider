package db

import "github.com/go-jose/go-jose/v3"

type DB interface {
	Seed() error

	SaveAccountKey(accountID []byte, key *jose.JSONWebKey) error
	GetAccountKey(accountID []byte) (*jose.JSONWebKey, error)

	GetAccount(accountID []byte) (*DBAccount, error)
	CreateAccount(acc DBAccount, key *jose.JSONWebKey) error
	UpdateAccount(accountID []byte, updateCallback func(*DBAccount) error) (*DBAccount, error)
	DeleteAccount(accountID []byte) error

	GetOrder(orderID []byte) (*DBOrder, error)
	CreateOrder(DBOrder) error
	UpdateOrder(orderID []byte, updateCallback func(*DBOrder) error) (*DBOrder, error)
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

	NotBefore int64 `json:"not_before"`
	NotAfter  int64 `json:"not_after"`

	Identifiers []DBOrderIdentifier `json:"identifiers"`

	AuthzIDs []string `json:"authz_ids"`
}

type DBOrderIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
