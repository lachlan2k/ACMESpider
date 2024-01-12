package acme_controller

import (
	"github.com/go-acme/lego/v4/lego"
	"github.com/lachlan2k/acmespider/internal/db"
	"github.com/lachlan2k/acmespider/internal/links"
)

type ACMEController struct {
	db         db.DB
	acmeClient *lego.Client
	linkCtrl   links.LinkController
}

func New(db db.DB, acmeClient *lego.Client, linkCtrl links.LinkController) *ACMEController {
	return &ACMEController{
		db:         db,
		acmeClient: acmeClient,
		linkCtrl:   linkCtrl,
	}
}
