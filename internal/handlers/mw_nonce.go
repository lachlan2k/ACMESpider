package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
)

func (h Handlers) AddNonceMw(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := h.AddNonce(c)
		if err != nil {
			return err
		}
		return next(c)
	}
}

func (h Handlers) AddNonce(c echo.Context) error {
	headers := c.Response().Header()

	nonce, err := h.NonceCtrl.Gen()
	if err != nil {
		return acme_controller.InternalErrorProblem(err)
	}

	headers.Set("Replay-Nonce", nonce)
	headers.Set("Cache-Control", "no-store")

	return nil
}
