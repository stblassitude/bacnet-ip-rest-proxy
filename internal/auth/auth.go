// Package auth authenticates the Authorization: Bearer header of an
// incoming request, recognizing either an opaque token from
// authentication.tokens or a JWT signed with the configured shared secret.
package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

// Token is one entry of authentication.tokens.
type Token struct {
	Name  string
	Value string
}

// Authenticator recognizes bearer credentials against a configured set of
// opaque tokens and/or a JWT signing secret.
type Authenticator struct {
	tokensByValue map[string]string // token value -> name
	jwtSecret     []byte
}

// Options configures an Authenticator.
type Options struct {
	Tokens []Token
	// JWTSecret is the HMAC-SHA256 shared secret used to verify JWT
	// bearers. If empty, JWT bearers are never considered valid.
	JWTSecret string
}

func NewAuthenticator(opts Options) *Authenticator {
	a := &Authenticator{tokensByValue: make(map[string]string, len(opts.Tokens))}
	for _, tok := range opts.Tokens {
		a.tokensByValue[tok.Value] = tok.Name
	}
	if opts.JWTSecret != "" {
		a.jwtSecret = []byte(opts.JWTSecret)
	}
	return a
}

// Result describes what, if anything, a bearer credential resolved to.
type Result struct {
	// TokenName is set if bearer matched a configured opaque token.
	TokenName string
	// Claims is set if bearer was a validly-signed JWT.
	Claims map[string]any
}

// Authenticate inspects a raw bearer credential (the value following
// "Bearer " in the Authorization header). An opaque token match takes
// precedence; otherwise the credential is parsed and verified as a JWT. A
// credential that is neither yields a zero Result (not an error) — it is up
// to the authorization engine to decide whether anonymous/unrecognized
// access is permitted.
func (a *Authenticator) Authenticate(bearer string) Result {
	if bearer == "" {
		return Result{}
	}
	if name, ok := a.tokensByValue[bearer]; ok {
		return Result{TokenName: name}
	}
	if a.jwtSecret == nil {
		return Result{}
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(bearer, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return a.jwtSecret, nil
	})
	if err != nil {
		return Result{}
	}
	return Result{Claims: claims}
}
