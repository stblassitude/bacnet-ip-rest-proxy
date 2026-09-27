package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
)

// clientIP returns the connecting client's IP, honoring
// X-Forwarded-For/X-Real-IP only when the immediate TCP peer is a
// configured trusted proxy — otherwise a client could simply set those
// headers itself to spoof its way past an `ip` authorization condition.
//
// Only a single trusted hop is supported: when trusted, the leftmost
// X-Forwarded-For entry (the original client, by convention) is used, on
// the assumption that entry was set by that trusted proxy itself rather
// than forwarded verbatim from a further-upstream, untrusted client.
func (s *Server) clientIP(r *http.Request) net.IP {
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}
	peer := net.ParseIP(peerHost)

	if s.isTrustedProxy(peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
				return ip
			}
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			if ip := net.ParseIP(strings.TrimSpace(xrip)); ip != nil {
				return ip
			}
		}
	}
	return peer
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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
		ClientIP:  s.clientIP(r),
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
