package acme_controller

import (
	"github.com/lachlan2k/acmespider/internal/db"
)

func (ac ACMEController) GetCertificate(accountID []byte, certID []byte) ([]byte, error) {
	dbCert, err := ac.db.GetCertificate([]byte(certID))
	if err != nil {
		if db.IsErrNotFound(err) {
			return nil, UnauthorizedProblem("")
		}
		return nil, InternalErrorProblem(err)
	}
	if dbCert == nil {
		return nil, UnauthorizedProblem("")
	}
	if dbCert.AccountID != string(accountID) {
		return nil, UnauthorizedProblem("")
	}

	return dbCert.Certificate, nil
}
