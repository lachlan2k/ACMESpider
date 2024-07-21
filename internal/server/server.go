package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"path"
	"time"

	"crypto/elliptic"
	"crypto/rand"
	mrand "math/rand"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/go-acme/lego/challenge"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	dnsProviders "github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/handlers"
	"github.com/lachlan2k/acmespider/internal/links"
	"github.com/lachlan2k/acmespider/internal/nonce"
	mhAcme "github.com/mholt/acmez/acme"

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
	PublicDNSResolvers []string
	Port               string
	Email              string
	CADirectory        string
	DNSProvider        string
	StoragePath        string
	BaseURL            string
	UseTLS             bool
	Hostname           string
	KeyType            certcrypto.KeyType

	MetaTosURL  string
	MetaCAAs    []string
	MetaWebsite string
}

func Listen(conf Config) error {
	app := echo.New()

	app.Use(makeLoggerMiddleware())
	app.Use(middleware.Recover())

	acmeAPI := app.Group("/acme")

	boltDb, err := db.NewBoltDb(path.Join(conf.StoragePath, "acmespider.db"))
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
	marshalledPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	myUser := MyUser{
		Email: conf.Email,
		key:   privateKey,
	}

	legoConfig := lego.NewConfig(&myUser)
	legoConfig.CADirURL = conf.CADirectory
	legoConfig.Certificate.KeyType = conf.KeyType

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return err
	}

	prov, err := dnsProviders.NewDNSChallengeProviderByName(conf.DNSProvider)
	if err != nil {
		return err
	}
	legoClient.Challenge.SetDNS01Provider(prov, dns01.AddRecursiveNameservers(conf.PublicDNSResolvers))
	log.Infof("Using DNS provider %s", conf.DNSProvider)

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
		BaseURL:     fullBaseURL + "acme",
		MetaTosURL:  conf.MetaTosURL,
		MetaCAAs:    conf.MetaCAAs,
		MetaWebsite: conf.MetaWebsite,
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

	if !conf.UseTLS {
		log.Info("Listening on plain HTTP...")
		return app.Start(":" + conf.Port)
	}

	log.Info("Configuring certmagic and listening with TLS...")
	certmagic.DefaultACME.DNS01Solver = solverWrapper{
		legoProvider: prov,
		resolvers:    conf.PublicDNSResolvers,
	}
	certmagic.DefaultACME.Email = conf.Email
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true
	certmagic.DefaultACME.CA = conf.CADirectory
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.AccountKeyPEM = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: marshalledPrivateKey,
		},
	))
	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: path.Join(conf.StoragePath, "certmagic"),
	}

	tlsConf, err := certmagic.TLS([]string{conf.Hostname})
	if err != nil {
		return err
	}

	s := http.Server{
		Addr:      ":" + conf.Port,
		Handler:   app,
		TLSConfig: tlsConf,
	}
	return s.ListenAndServeTLS("", "")
}

type solverWrapper struct {
	legoProvider challenge.Provider
	resolvers    []string
}

func (s solverWrapper) Present(ctx context.Context, chall mhAcme.Challenge) error {
	return s.legoProvider.Present(chall.Identifier.Value, chall.Token, chall.KeyAuthorization)
}
func (s solverWrapper) CleanUp(ctx context.Context, chall mhAcme.Challenge) error {
	return s.legoProvider.CleanUp(chall.Identifier.Value, chall.Token, chall.KeyAuthorization)
}
func (s solverWrapper) Wait(inCtx context.Context, chall mhAcme.Challenge) error {
	info := dns01.GetChallengeInfo(chall.Identifier.Value, chall.KeyAuthorization)
	fqdn := info.EffectiveFQDN

	timeout := 300 * time.Second
	interval := 30 * time.Second

	ctx, cancel := context.WithDeadline(inCtx, time.Now().Add(timeout))
	defer cancel()

	log.WithField("fqdn", fqdn).WithField("value", info.Value).Debug("Starting DNS record propagation check")

	r := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			resolver := s.resolvers[mrand.Intn(len(s.resolvers))]
			if !strings.Contains(resolver, ":") {
				resolver = resolver + ":53"
			}

			d := net.Dialer{
				Timeout: time.Second * 10,
			}
			return d.DialContext(ctx, network, resolver)
		},
	}

	for {
		select {
		case <-ctx.Done():
			log.WithField("fqdn", fqdn).Debug("Timed out waiting for ACME DNS record propagation")
			return nil
		case <-time.After(interval):
		}

		lookupCtx, cancelLookup := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
		defer cancelLookup()

		log.WithField("fqdn", fqdn).Debug("Looking up record for ACME verification to check propagation")
		answers, err := r.LookupTXT(lookupCtx, fqdn)
		if err != nil {
			log.WithField("fqdn", fqdn).WithError(err).Debug("Failed to lookup ACME record")
			continue
		}

		for _, ans := range answers {
			if ans == info.Value {
				log.WithField("fqdn", fqdn).Debug("ACME record propagated!")
				return nil
			}
			log.WithField("fqdn", fqdn).WithField("exepcted_value", info.Value).WithField("found_value", ans).Debug("TXT result didn't match")
		}
	}
}
