package acme_controller

import (
	"encoding/pem"

	"github.com/lachlan2k/acmespider/internal/db"
)

func (ac ACMEController) GetCertificate(accountID []byte, certID []byte) ([]byte, error) {
	cert, err := ac.db.GetCertificate([]byte(certID))
	if err != nil {
		if db.IsErrNotFound(err) {
			return nil, UnauthorizedProblem("")
		}
		return nil, InternalErrorProblem(err)
	}
	if cert == nil {
		return nil, UnauthorizedProblem("")
	}
	if cert.AccountID != string(accountID) {
		return nil, UnauthorizedProblem("")
	}

	pemOutput := []byte{}
	pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.CertificateDER,
	})
	if len(cert.IssuerCertificate) > 0 {
		pemOutput = append(pemOutput, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.IssuerCertificate,
		})...)
	}

	return pemOutput, nil
}
