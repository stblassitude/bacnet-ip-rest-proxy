package api

import (
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
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

// caller is an authenticated (or anonymous) request's identity, ready to
// be evaluated against the rules once per operation and variable.
type caller struct {
	bearer string
	req    authz.Request
}

func (s *Server) newCaller(r *http.Request, device string) caller {
	bearer := bearerToken(r)
	authResult := s.authenticator.Authenticate(bearer)
	return caller{bearer: bearer, req: authz.Request{
		Device:    device,
		ClientIP:  s.clientIP(r),
		TokenName: authResult.TokenName,
		JWTClaims: authResult.Claims,
	}}
}

// allowed reports whether c may perform op on the variable named name ("" for
// requests not about a single variable), including holding readwrite
// permission for write operations.
func (s *Server) allowed(c caller, name string, op authz.Operation) bool {
	req := c.req
	req.Operation = op
	req.ObjectName = name
	result := authz.Evaluate(req, s.rules)
	return result.Allowed && (op.RequiredPermission() != authz.PermissionReadWrite || result.Permission == authz.PermissionReadWrite)
}

// access is a caller's effective right on one variable.
type access string

const (
	accessNone      access = ""
	accessReadOnly  access = "readonly"
	accessReadWrite access = "readwrite"
)

// variableAccess derives c's right on the variable named name: visible if
// it may read-property it, and readwrite if it may also write-property it.
func (s *Server) variableAccess(c caller, name string) access {
	if !s.allowed(c, name, authz.OperationReadProperty) {
		return accessNone
	}
	if s.allowed(c, name, authz.OperationWriteProperty) {
		return accessReadWrite
	}
	return accessReadOnly
}

// authorize enforces authentication and authorization for a request that
// isn't about a single variable: device (which may be "" for endpoints that
// don't target a specific device) performing op. `variable` conditions never
// match such a request. On failure it has already written the HTTP response
// and the caller must not proceed.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, device string, op authz.Operation) (caller, bool) {
	c := s.newCaller(r, device)
	return c, s.check(w, c, "", op)
}

// authorizeVariable is authorize for a request about one variable of
// device: obj, or the device's own Device object if obj is nil. When any
// rule has a `variable` condition, the variable's name comes from the
// variable cache; a variable missing from it (or a device that can't be
// enumerated) is denied, since evaluating it without a name would silently
// skip any deny rule keyed on a name. It returns the caller and the
// variable's name ("" when no rule looks at names).
func (s *Server) authorizeVariable(w http.ResponseWriter, r *http.Request, device string, obj *bacnet.ObjectIdentifier, op authz.Operation) (caller, string, bool) {
	c := s.newCaller(r, device)
	if !s.needsObjectName {
		// No rule looks at variable names: every variable of the device
		// gets the same verdict, and nothing needs to be enumerated first.
		return c, "", s.check(w, c, "", op)
	}
	dv, err := s.cache.get(s.resolveDevice(device))
	if err != nil {
		s.writeEnumerationError(w, c, device, err)
		return c, "", false
	}
	id := dv.deviceObject()
	if obj != nil {
		id = *obj
	}
	v, ok := dv.byID[id]
	if !ok {
		slog.Info("denying request: object not in the device's cached variable list", "device", device, "object", id.Type.String(), "instance", id.Instance)
		writeDenied(w, c.bearer)
		return c, "", false
	}
	return c, v.Name, s.check(w, c, v.Name, op)
}

// check evaluates op on the variable named name for c, writing the error
// response if it's not allowed.
func (s *Server) check(w http.ResponseWriter, c caller, name string, op authz.Operation) bool {
	if s.allowed(c, name, op) {
		return true
	}
	if op.RequiredPermission() == authz.PermissionReadWrite && s.allowed(c, name, authz.OperationReadProperty) {
		writeError(w, http.StatusForbidden, "readwrite permission required for this operation")
		return false
	}
	writeDenied(w, c.bearer)
	return false
}

// writeEnumerationError refuses a request whose authorization needed the
// device's variables, which couldn't be read. A caller with a recognized
// credential gets the underlying BACnet error, so a misbehaving device
// doesn't masquerade as a permissions problem; anyone else just gets
// 401/403, without learning anything about the device.
func (s *Server) writeEnumerationError(w http.ResponseWriter, c caller, device string, err error) {
	slog.Warn("refusing request: could not enumerate device variables for authorization", "device", device, "err", err)
	if c.req.TokenName != "" || c.req.JWTClaims != nil {
		writeBACnetError(w, err)
		return
	}
	writeDenied(w, c.bearer)
}

func writeDenied(w http.ResponseWriter, bearer string) {
	if bearer == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "authentication required")
	} else {
		writeError(w, http.StatusForbidden, "access denied")
	}
}

// recoverJSON turns a panic in a handler into a logged 500 with a JSON
// error body, instead of chi's Recoverer's empty one.
func recoverJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				slog.Error("panic serving request", "method", r.Method, "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
