package server

import (
	"errors"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	log "github.com/sirupsen/logrus"
)

func makeLoggerMiddleware() echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(
		middleware.RequestLoggerConfig{

			LogError:         true,
			LogLatency:       true,
			LogRemoteIP:      true,
			LogMethod:        true,
			LogURI:           true,
			LogUserAgent:     true,
			LogStatus:        true,
			LogContentLength: true,
			LogResponseSize:  true,

			LogValuesFunc: func(c echo.Context, values middleware.RequestLoggerValues) error {
				fields := log.Fields{
					"latency_ms":     values.Latency.Milliseconds(),
					"remote_ip":      values.RemoteIP,
					"method":         values.Method,
					"URI":            values.URI,
					"user_agent":     values.UserAgent,
					"status":         values.Status,
					"content_length": values.ContentLength,
					"response_size":  values.ResponseSize,
				}

				if values.Error != nil {
					wrapped := &acme_controller.ProblemDetails{}
					if errors.As(values.Error, &wrapped) {
						if wrapped.Unwrap() != nil {
							// "Real error", i.e. probably a 500
							log.WithError(wrapped.Unwrap()).WithFields(fields).WithField("error_id", wrapped.ID()).Error("request error " + wrapped.ID())
						} else {
							// Generic problem
							log.WithError(wrapped).
								WithFields(fields).
								WithField("problem_type", wrapped.Type).
								WithField("problem_detail", wrapped.Detail).
								WithField("problem_status", wrapped.HTTPStatus).
								Warn("request problem")
						}
						return nil
					}
					log.WithError(values.Error).WithFields(fields).Error("generic request error")
					return nil
				}

				if values.Status >= 500 && values.Status <= 599 {
					log.WithFields(fields).Error("generic request error")
					return nil
				}

				if values.Status == 400 || values.Status == 403 {
					log.WithFields(fields).Warn("bad request")
					return nil
				}

				log.WithFields(fields).Info("request")
				return nil
			},
		},
	)
}
