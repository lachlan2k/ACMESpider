package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/lachlan2k/acmespider/internal/server"
	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
)

const envPort = "ACMESPIDER_PORT"
const envUseTLS = "ACMESPIDER_TLS"
const envBaseURL = "ACMESPIDER_BASE_URL"
const envHost = "ACMESPIDER_HOSTNAME"
const envStoragePath = "ACMESPIDER_STORAGE_PATH"

const envACMEPublicResolvers = "ACMESPIDER_PUBLIC_RESOLVERS"
const envACMEDNSProvider = "ACMESPIDER_DNS_PROVIDER"
const envACMEDirectory = "ACMESPIDER_ACME_CA_DIRECTORY"
const envACMETOSAccept = "ACMESPIDER_ACME_TOS_ACCEPT"
const envACMEEmail = "ACMESPIDER_ACME_EMAIL"
const envACMEKeyType = "ACMESPIDER_KEY_TYPE"
const envACMEMetaTosURL = "ACMESPIDER_META_TOS_URL"
const envACMEMetaCAAs = "ACMESPIDER_META_CAAS"
const envACMEMetaWebsite = "ACMESPIDER_META_WEBSITE"

func strIsTruthy(str string) bool {
	l := strings.TrimSpace(strings.ToLower(str))
	return l == "yes" || l == "true" || l == "1"
}

func getKeytype(keystr string) certcrypto.KeyType {
	l := strings.TrimSpace(strings.ToLower(keystr))
	switch l {
	case "rsa", "rsa2048":
		return certcrypto.RSA2048
	case "rsa3072":
		return certcrypto.RSA3072
	case "rsa4096":
		return certcrypto.RSA4096
	case "rsa8192":
		return certcrypto.RSA8192
	case "ec256":
		return certcrypto.EC256
	case "ec384":
		return certcrypto.EC384
	}
	return certcrypto.RSA2048
}

func runServe(cCtx *cli.Context) error {
	port := os.Getenv(envPort)
	if port == "" {
		port = "443"
	}

	useTLS := false
	useTLSStr := os.Getenv(envUseTLS)
	if strIsTruthy(useTLSStr) || (useTLSStr == "" && port == "443") {
		useTLS = true
	}

	if !strIsTruthy(os.Getenv(envACMETOSAccept)) {
		return fmt.Errorf("please indicate that you accept the terms-of-service for your ACME provider by setting %s=true", envACMETOSAccept)
	}

	baseURL := os.Getenv(envBaseURL)
	hostname := os.Getenv(envHost)

	hasHostname := hostname != ""
	hasBaseurl := baseURL != ""

	if !hasHostname && !hasBaseurl {
		return fmt.Errorf("please provide a base URL in %s and/or a hostname in %s", envBaseURL, envHost)
	}

	if hasBaseurl && !hasHostname {
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return fmt.Errorf("failed to parse provided baseurl: %v", err)
		}
		hostname = parsed.Host
		log.Infof("Using hostname %q for TLS, parsed from base URL", hostname)
	} else if hasHostname && !hasBaseurl {
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		hostForURL := hostname
		if (scheme == "http" && port != "80") || (scheme == "https" && port != "443") {
			hostForURL += ":" + port
		}

		baseURL = (&url.URL{
			Scheme: scheme,
			Host:   hostForURL,
		}).String()
		log.Infof("Using base URL %q calculated from host, port, and scheme", baseURL)
	}

	dnsProv := os.Getenv(envACMEDNSProvider)

	acmeDirectory := os.Getenv(envACMEDirectory)
	if acmeDirectory == "" {
		acmeDirectory = lego.LEDirectoryProduction
		log.Infof("No ACME directory specified, defaulting to %s", acmeDirectory)
	}

	acmeEmail := os.Getenv(envACMEEmail)
	if acmeEmail == "" {
		log.Warnf("No email was provided to %s. Most ACME providers require this, please consider setting one.", envACMEEmail)
	}

	storagepath := os.Getenv(envStoragePath)
	if storagepath == "" {
		storagepath = "./"
	}

	dnsServerStr := os.Getenv(envACMEPublicResolvers)
	publicServers := []string{"1.1.1.1", "8.8.8.8"}
	if dnsServerStr != "" {
		publicServers = strings.Split(dnsServerStr, ",")
	} else {
		log.Infof("Using default public DNS resolvers of %v", publicServers)
	}

	return server.Listen(server.Config{
		Port:               port,
		Email:              acmeEmail,
		CADirectory:        acmeDirectory,
		DNSProvider:        dnsProv,
		BaseURL:            baseURL,
		StoragePath:        storagepath,
		UseTLS:             useTLS,
		Hostname:           hostname,
		KeyType:            getKeytype(os.Getenv(envACMEKeyType)),
		PublicDNSResolvers: publicServers,

		MetaTosURL:  os.Getenv(envACMEMetaTosURL),
		MetaCAAs:    strings.Split(os.Getenv(envACMEMetaCAAs), ","),
		MetaWebsite: os.Getenv(envACMEMetaWebsite),
	})
}

func main() {
	log.SetLevel(log.DebugLevel)

	app := &cli.App{
		Name:        "ACMESpider",
		Description: "ACMESpider",
		Commands: []*cli.Command{
			{
				Name:   "serve",
				Usage:  "run the ACMESpider server",
				Action: runServe,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
