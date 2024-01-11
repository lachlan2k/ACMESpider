package dtos

type DirectoryMetaResponseDTO struct {
	TOS                     string   `json:"termsOfService"`
	Website                 string   `json:"website"`
	CAAIdentities           []string `json:"caaIdentities"`
	ExternalAccountRequired bool     `json:"externalAccountRequired"`
}

type DirectoryListResponseDTO struct {
	NewNonce   string                   `json:"newNonce"`
	NewAccount string                   `json:"newAccount"`
	NewOrder   string                   `json:"newOrder"`
	NewAuthz   string                   `json:"newAuthz"`
	RevokeCert string                   `json:"revokeCert"`
	KeyChange  string                   `json:"keyChange"`
	Meta       DirectoryMetaResponseDTO `json:"meta"`
}
