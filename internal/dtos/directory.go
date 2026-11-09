package dtos

type DirectoryMetaResponseDTO struct {
	TOS                     string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired"`
}

type DirectoryListResponseDTO struct {
	NewNonce   string                   `json:"newNonce"`
	NewAccount string                   `json:"newAccount"`
	NewOrder   string                   `json:"newOrder"`
	NewAuthz   string                   `json:"newAuthz,omitempty"`
	RevokeCert string                   `json:"revokeCert"`
	KeyChange  string                   `json:"keyChange"`
	Meta       DirectoryMetaResponseDTO `json:"meta"`
}
