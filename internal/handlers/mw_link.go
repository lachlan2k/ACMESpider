package handlers

import "github.com/labstack/echo/v4"

func (h Handlers) AddIndexLinkMw(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		h.addLink(c, h.LinkCtrl.DirectoryPath().Abs(), "index")
		return next(c)
	}
}
