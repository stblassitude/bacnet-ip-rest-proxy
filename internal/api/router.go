package api

import (
	_ "embed"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

//go:embed openapi.yaml
var openAPISpec []byte

// NewRouter builds the full HTTP handler: the versioned REST API, the raw
// OpenAPI spec, and an offline-rendered Swagger UI.
func NewRouter(s *Server) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	// Deliberately not using chi's RealIP middleware: it trusts
	// X-Forwarded-For/X-Real-IP unconditionally, which would let a client
	// spoof the IP that authz's `ip` condition matches against. clientIP()
	// in middleware.go reads r.RemoteAddr (the actual TCP peer) directly.

	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(openAPISpec)
	})
	r.Get("/docs/*", httpSwagger.Handler(httpSwagger.URL("/openapi.yaml")))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/devices", s.handleListDevices)
		r.Get("/devices/{deviceId}", s.handleGetDevice)
		r.Get("/devices/{deviceId}/objects", s.handleListObjects)
		r.Get("/devices/{deviceId}/objects/{objectType}/{instance}", s.handleGetObject)
		r.Get("/devices/{deviceId}/objects/{objectType}/{instance}/{property}", s.handleGetProperty)
		r.Put("/devices/{deviceId}/objects/{objectType}/{instance}/{property}", s.handleWriteProperty)
	})

	return r
}
