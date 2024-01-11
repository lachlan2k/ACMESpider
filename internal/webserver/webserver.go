package webserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/lachlan2k/acmespider/internal/handlers"
	"github.com/lachlan2k/acmespider/internal/links"
	"github.com/lachlan2k/acmespider/internal/nonce"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/sirupsen/logrus"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func Listen(port string) {
	app := echo.New()

	app.Use(makeLoggerMiddleware())
	app.Use(middleware.Recover())

	acmeAPI := app.Group("/acme")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: "lachlan+as@lachlan.nz",
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	l := links.LinkController{
		BaseURL: "http://localhost:" + port + "/acme",
	}

	h := handlers.Handlers{
		Client:    client,
		NonceCtrl: nonce.NewInMemCtrl(),
		LinkCtrl:  l,
	}

	acmeAPI.Use(h.AddIndexLinkMw)

	acmeAPI.GET(l.NewNoncePath().Relative(), h.GetNonce, h.AddNonceMw)
	acmeAPI.HEAD(l.NewNoncePath().Relative(), h.GetNonce, h.AddNonceMw)
	acmeAPI.GET(l.DirectoryPath().Relative(), h.GetDirectory)
	acmeAPI.HEAD(l.DirectoryPath().Relative(), h.GetDirectory)

	acmeAPI.POST(l.NewAccountPath().Relative(), h.NewAccount, h.AddNonceMw, h.ValidateJWSWithJWKAndExtractPayload)
	acmeAPI.POST(l.AccountPath(":"+l.AccountIDParam()).Relative(), h.GetOrUpdateAccount, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)
	acmeAPI.POST(l.AccountKeyChangePath().Relative(), h.NotImplemented, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)

	acmeAPI.POST(l.NewOrderPath().Relative(), h.NewOrder, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)
	acmeAPI.POST(l.OrderPath(":"+l.OrderIDParam()).Relative(), h.GetOrder, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)
	acmeAPI.POST(l.AccountOrdersPath(":"+l.AccountIDParam()).Relative(), h.GetOrdersByAccountID, h.ValidateJWSWithKIDAndExtractPayload, h.AddNonceMw, h.POSTAsGETMw)
	acmeAPI.POST(l.FinalizeOrderPath(":"+l.OrderIDParam()).Relative(), h.FinalizeOrder, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)

	acmeAPI.POST(l.AuthzPath(":"+l.AuthzIDParam()).Relative(), h.GetAuthorization, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload, h.POSTAsGETMw)
	acmeAPI.POST(l.ChallengePath(":"+l.AuthzIDParam(), ":"+l.ChallengeIDParam()).Relative(), h.GetChallenge, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload, h.ValidateJWSWithKIDAndExtractPayload)
	acmeAPI.POST(l.CertPath(":"+l.CertIDParam()).Relative(), h.GetCertificate, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload, h.POSTAsGETMw)
	acmeAPI.POST(l.RevokeCertPath().Relative(), h.RevokeCert, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)

	err = app.Start(":" + port)
	if err != nil {
		log.Fatal(err)
	}
}
