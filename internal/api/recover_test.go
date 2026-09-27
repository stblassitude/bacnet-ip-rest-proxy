package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoverJSONReportsPanicAsJSONError(t *testing.T) {
	h := recoverJSON(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"error":"internal error"`) {
		t.Fatalf("got body %q, want a JSON error", body)
	}
}
