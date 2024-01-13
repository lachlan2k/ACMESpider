package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/lego"
	"github.com/lachlan2k/acmespider/internal/server"
	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
)

const envPort = "ACMESPIDER_PORT"
const envACMEDNSProvider = "ACMESPIDER_DNS_PROVIDER"
const envACMEDirectory = "ACMESPIDER_ACME_DIRECTORY"
const envACMETOSAccept = "ACMESPIDER_ACME_TOS_ACCEPT"
const envACMEEmail = "ACMESPIDER_ACME_EMAIL"
const envBaseURL = "ACMESPIDER_BASE_URL"
const envDBPath = "ACMESPIDER_DB_PATH"

func runServe(cCtx *cli.Context) error {
	port := os.Getenv(envPort)
	if port == "" {
		port = "443"
	}

	lcTosAccept := strings.TrimSpace(strings.ToLower(os.Getenv(envACMETOSAccept)))
	if lcTosAccept != "yes" && lcTosAccept != "true" && lcTosAccept != "1" {
		return fmt.Errorf("Please indicate that you accept the terms-of-service for your ACME provider by setting %s=true", envACMETOSAccept)
	}

	baseURL := os.Getenv(envBaseURL)
	if baseURL == "" {
		return fmt.Errorf("Please provide a base URL in %s", envBaseURL)
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

	dbPath := os.Getenv(envDBPath)
	if dbPath == "" {
		dbPath = "./acmespider.db"
	}

	return server.Listen(server.Config{
		Port:        port,
		Email:       acmeEmail,
		Directory:   acmeDirectory,
		DNSProvider: dnsProv,
		BaseURL:     baseURL,
		DBPath:      dbPath,
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
