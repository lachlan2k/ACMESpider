package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"crypto/elliptic"
	"crypto/rand"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	dnsProviders "github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/db"
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

type Config struct {
	Port        string
	Email       string
	Directory   string
	DNSProvider string
	DBPath      string
	BaseURL     string
	KeyType     certcrypto.KeyType
}

func Listen(conf Config) error {
	app := echo.New()

	app.Use(makeLoggerMiddleware())
	app.Use(middleware.Recover())

	acmeAPI := app.Group("/acme")

	boltDb, err := db.NewBoltDb(conf.DBPath)
	if err != nil {
		return err
	}

	var privateKey *ecdsa.PrivateKey
	existingMarshalledPrivateKey, err := boltDb.GetGlobalKey()
	if err != nil {
		if !db.IsErrNotFound(err) {
			return err
		}

		// FIrst time, gen key
		log.Info("Generating keypair...")
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		marshalledPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return err
		}
		err = boltDb.SaveGlobalKey(marshalledPrivateKey)
		if err != nil {
			return err
		}
	} else {
		log.Info("Using existing keypair...")
		privateKey, err = x509.ParseECPrivateKey(existingMarshalledPrivateKey)
		if err != nil {
			return fmt.Errorf("couldn't unmarshal existing private key: %v", err)
		}
	}

	myUser := MyUser{
		Email: conf.Email,
		key:   privateKey,
	}

	legoConfig := lego.NewConfig(&myUser)
	legoConfig.CADirURL = conf.Directory
	legoConfig.Certificate.KeyType = conf.KeyType

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return err
	}

	if conf.DNSProvider != "" {
		prov, err := dnsProviders.NewDNSChallengeProviderByName(conf.DNSProvider)
		if err != nil {
			return err
		}
		legoClient.Challenge.SetDNS01Provider(prov)
		log.Printf("Using DNS provider %s", conf.DNSProvider)
	} else {
		log.Printf("Using HTTP-01 for solving challenges with %s. Ensure your ACMESpider instance is accessible by your provider", conf.Directory)
	}

	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	myUser.Registration = reg

	fullBaseURL := conf.BaseURL
	if !strings.HasSuffix(fullBaseURL, "/") {
		fullBaseURL += "/"
	}

	l := links.LinkController{
		BaseURL: fullBaseURL + "acme",
	}

	acmeCtrl := acme_controller.New(boltDb, legoClient, l)

	h := handlers.Handlers{
		AcmeCtrl:  acmeCtrl,
		NonceCtrl: nonce.NewInMemCtrl(),
		LinkCtrl:  l,
	}

	app.HTTPErrorHandler = h.ErrorHandler(app)

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
	acmeAPI.POST(l.ChallengePath(":"+l.ChallengeIDParam()).Relative(), h.InitiateChallenge, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)
	acmeAPI.POST(l.CertPath(":"+l.CertIDParam()).Relative(), h.GetCertificate, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload, h.POSTAsGETMw)
	acmeAPI.POST(l.RevokeCertPath().Relative(), h.RevokeCert, h.AddNonceMw, h.ValidateJWSWithKIDAndExtractPayload)

	return app.Start(":" + conf.Port)
}
