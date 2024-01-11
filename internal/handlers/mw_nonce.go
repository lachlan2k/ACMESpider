package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/util"
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

func (h Handlers) ConsumeNonceMw(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		nonce := c.Request().Header.Get("Replay-Nonce")
		if len(nonce) == 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Missing Replay-Nonce Header")
		}

		isNonceValid, err := h.NonceCtrl.ValidateAndConsume(nonce)
		if !isNonceValid || err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid Replay-Nonce")
		}

		err = h.AddNonce(c)
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
		return util.ServerError("internal server error", err)
	}

	headers.Set("Replay-Nonce", nonce)
	headers.Set("Cache-Control", "no-store")

	return nil
}
