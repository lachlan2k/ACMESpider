package links

import (
	"strings"

	"github.com/lachlan2k/acmespider/internal/dtos"
)

type Path struct {
	relative string
	abs      string
}

func (l Path) Abs() string {
	return l.abs
}

func (l Path) Relative() string {
	return l.relative
}

type LinkController struct {
	BaseURL string
}

func (l LinkController) Path(relative string) Path {
	if !strings.HasPrefix(relative, "/") {
		relative = "/" + relative
	}

	return Path{
		relative: relative,
		abs:      l.BaseURL + relative,
	}
}

func (l LinkController) CompareURL(requestPath string, toCompare string) bool {
	baseWithoutAcme := strings.TrimSuffix(l.BaseURL, "/acme")
	return (baseWithoutAcme + requestPath) == toCompare
}

func (l LinkController) NewNoncePath() Path {
	return l.Path("new-nonce")
}

func (l LinkController) DirectoryPath() Path {
	return l.Path("directory")
}

func (l LinkController) NewAccountPath() Path {
	return l.Path("new-account")
}

func (l LinkController) AccountPath(accountID string) Path {
	return l.Path("account/" + accountID)
}

func (l LinkController) AccountKeyChangePath() Path {
	return l.Path("key-change")
}

func (l LinkController) NewOrderPath() Path {
	return l.Path("new-order")
}

func (l LinkController) AccountOrdersPath(accountID string) Path {
	return l.Path("account/" + accountID + "/orders")
}

func (l LinkController) OrderPath(orderID string) Path {
	return l.Path("order/" + orderID)
}

func (l LinkController) FinalizeOrderPath(orderID string) Path {
	return l.Path("order/" + orderID + "/finalize")
}

func (l LinkController) NewAuthzPath() Path {
	return l.Path("new-authz")
}

func (l LinkController) AuthzPath(authzID string) Path {
	return l.Path("authz/" + authzID)
}

func (l LinkController) ChallengePath(challengeID string) Path {
	return l.Path("chall/" + challengeID)
}

func (l LinkController) CertPath(certID string) Path {
	return l.Path("certificate/" + certID)
}

func (l LinkController) RevokeCertPath() Path {
	return l.Path("revoke-cert")
}

func (l LinkController) AccountIDParam() string {
	return "accID"
}

func (l LinkController) OrderIDParam() string {
	return "orderID"
}

func (l LinkController) AuthzIDParam() string {
	return "authzID"
}

func (l LinkController) ChallengeIDParam() string {
	return "chID"
}

func (l LinkController) CertIDParam() string {
	return "certID"
}

func (l LinkController) GenerateDirectory() dtos.DirectoryListResponseDTO {
	return dtos.DirectoryListResponseDTO{
		NewNonce:   l.NewNoncePath().Abs(),
		NewAccount: l.NewAccountPath().Abs(),
		NewOrder:   l.NewOrderPath().Abs(),
		NewAuthz:   l.NewAuthzPath().Abs(),
		RevokeCert: l.RevokeCertPath().Abs(),
		KeyChange:  l.AccountKeyChangePath().Abs(),
	}
}
