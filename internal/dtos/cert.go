package dtos

type RevokeCertRequestDTO struct {
	CertificateB64 string `json:"certificate"`
	Reason         *uint  `json:"reason"`
}
