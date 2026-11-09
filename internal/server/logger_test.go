package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/acmespider/internal/acme_controller"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// serve runs one request through the logger middleware with a handler that behaves as given,
// and returns the single log entry that was written.
func serve(t *testing.T, handler echo.HandlerFunc) *log.Entry {
	t.Helper()

	hook := logtest.NewLocal(log.StandardLogger())
	t.Cleanup(func() { hook.Reset() })
	prev := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetLevel(prev) })

	app := echo.New()
	app.Use(makeLoggerMiddleware())
	app.HTTPErrorHandler = func(err error, c echo.Context) {
		var pd *acme_controller.ProblemDetails
		if errors.As(err, &pd) {
			c.JSON(pd.HTTPStatus, pd)
			return
		}
		app.DefaultHTTPErrorHandler(err, c)
	}
	app.POST("/x", handler)

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("User-Agent", "test-agent")
	app.ServeHTTP(httptest.NewRecorder(), req)

	if len(hook.AllEntries()) != 1 {
		t.Fatalf("expected exactly one log entry, got %d", len(hook.AllEntries()))
	}
	return hook.LastEntry()
}

func TestLoggerMiddleware(t *testing.T) {
	t.Run("successful request is info", func(t *testing.T) {
		e := serve(t, func(c echo.Context) error { return c.NoContent(http.StatusOK) })

		if e.Level != log.InfoLevel || e.Message != "request" {
			t.Errorf("level=%s message=%q", e.Level, e.Message)
		}
		for k, want := range map[string]any{"method": "POST", "URI": "/x", "user_agent": "test-agent", "status": 200} {
			if e.Data[k] != want {
				t.Errorf("field %s = %v, want %v", k, e.Data[k], want)
			}
		}
		for _, k := range []string{"latency_ms", "remote_ip", "content_length", "response_size"} {
			if _, ok := e.Data[k]; !ok {
				t.Errorf("missing field %s", k)
			}
		}
	})

	t.Run("problem is a warning with details and no internal cause", func(t *testing.T) {
		e := serve(t, func(c echo.Context) error { return acme_controller.MalformedProblem("bad body") })

		if e.Level != log.WarnLevel || e.Message != "request problem" {
			t.Fatalf("level=%s message=%q", e.Level, e.Message)
		}
		if e.Data["problem_detail"] != "bad body" || e.Data["problem_status"] != http.StatusBadRequest ||
			e.Data["problem_type"] != "urn:ietf:params:acme:error:malformed" {
			t.Errorf("fields = %v", e.Data)
		}
	})

	t.Run("internal problem logs the real cause against its error id", func(t *testing.T) {
		pd := acme_controller.InternalErrorProblem(errors.New("db exploded"))
		e := serve(t, func(c echo.Context) error { return pd })

		if e.Level != log.ErrorLevel || e.Message != "request error "+pd.ID() {
			t.Fatalf("level=%s message=%q", e.Level, e.Message)
		}
		if e.Data["error_id"] != pd.ID() {
			t.Errorf("error_id = %v, want %s", e.Data["error_id"], pd.ID())
		}
		if err, _ := e.Data[log.ErrorKey].(error); err == nil || err.Error() != "db exploded" {
			t.Errorf("logged error = %v, want the wrapped cause", e.Data[log.ErrorKey])
		}
	})

	t.Run("non-problem error is an error", func(t *testing.T) {
		e := serve(t, func(c echo.Context) error { return errors.New("boom") })
		if e.Level != log.ErrorLevel || e.Message != "generic request error" {
			t.Errorf("level=%s message=%q", e.Level, e.Message)
		}
	})
}
