package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
)

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}

// authorize enforces authentication and authorization for a request
// targeting device (which may be "" for endpoints that don't target a
// specific device) performing op. On success it returns true; on failure it
// has already written the HTTP response and the caller must not proceed.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, device string, op authz.Operation) bool {
	bearer := bearerToken(r)
	authResult := s.authenticator.Authenticate(bearer)

	req := authz.Request{
		Device:    device,
		ClientIP:  clientIP(r),
		Operation: op,
		TokenName: authResult.TokenName,
		JWTClaims: authResult.Claims,
	}
	result := authz.Evaluate(req, s.rules)

	if !result.Allowed {
		if bearer == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "authentication required")
		} else {
			writeError(w, http.StatusForbidden, "access denied")
		}
		return false
	}
	if op.RequiredPermission() == authz.PermissionReadWrite && result.Permission != authz.PermissionReadWrite {
		writeError(w, http.StatusForbidden, "readwrite permission required for this operation")
		return false
	}
	return true
}
