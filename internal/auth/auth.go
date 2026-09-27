// Package auth authenticates the Authorization: Bearer header of an
// incoming request, recognizing an opaque token from authentication.tokens,
// a JWT access token from a configured OpenID Connect issuer, or a JWT
// signed with the configured shared HMAC secret.
package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Token is one entry of authentication.tokens.
type Token struct {
	Name  string
	Value string
}

// Authenticator recognizes bearer credentials against a configured set of
// opaque tokens, OpenID Connect issuers and/or a JWT signing secret.
type Authenticator struct {
	tokensByValue map[string]string // token value -> name
	jwtSecret     []byte
	issuers       map[string]*oidcVerifier // issuer URL -> verifier
}

// Options configures an Authenticator.
type Options struct {
	Tokens []Token
	// JWTSecret is the HMAC shared secret used to verify HS256/384/512 JWT
	// bearers. If empty, HMAC-signed JWTs are never considered valid.
	JWTSecret string
	// Issuers are the OpenID Connect issuers whose (asymmetrically signed)
	// JWT access tokens are accepted.
	Issuers []Issuer
	// HTTPClient fetches issuer metadata; nil uses a default client.
	HTTPClient *http.Client
}

// NewAuthenticator builds an Authenticator and starts fetching each
// issuer's signing keys in the background.
func NewAuthenticator(opts Options) *Authenticator {
	a := &Authenticator{
		tokensByValue: make(map[string]string, len(opts.Tokens)),
		issuers:       make(map[string]*oidcVerifier, len(opts.Issuers)),
	}
	for _, tok := range opts.Tokens {
		a.tokensByValue[tok.Value] = tok.Name
	}
	if opts.JWTSecret != "" {
		a.jwtSecret = []byte(opts.JWTSecret)
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	for _, iss := range opts.Issuers {
		v := newOIDCVerifier(iss, client)
		a.issuers[iss.URL] = v
		v.prefetch()
	}
	return a
}

// Result describes what, if anything, a bearer credential resolved to.
type Result struct {
	// TokenName is set if bearer matched a configured opaque token.
	TokenName string
	// Claims is set if bearer was a valid JWT.
	Claims map[string]any
}

// Authenticate inspects a raw bearer credential (the value following
// "Bearer " in the Authorization header). An opaque token match takes
// precedence; otherwise the credential is verified as a JWT: HMAC-signed
// ones against the shared secret, asymmetrically signed ones against the
// signing keys of the configured issuer named in their iss claim. A
// credential that is none of these yields a zero Result (not an error) — it
// is up to the authorization engine to decide whether anonymous/unrecognized
// access is permitted.
func (a *Authenticator) Authenticate(ctx context.Context, bearer string) Result {
	if bearer == "" {
		return Result{}
	}
	if name, ok := a.tokensByValue[bearer]; ok {
		return Result{TokenName: name}
	}

	// Peek at the (not yet verified) header and issuer only to pick the
	// verifier; each verifier then checks the algorithm and issuer itself.
	unverified := jwt.MapClaims{}
	tok, _, err := jwt.NewParser().ParseUnverified(bearer, unverified)
	if err != nil {
		return Result{}
	}
	if strings.HasPrefix(tok.Method.Alg(), "HS") {
		return a.verifyHMAC(bearer)
	}
	iss, _ := unverified["iss"].(string)
	v, ok := a.issuers[iss]
	if !ok {
		return Result{}
	}
	claims, err := v.verify(ctx, bearer)
	if err != nil {
		return Result{}
	}
	return Result{Claims: claims}
}

func (a *Authenticator) verifyHMAC(bearer string) Result {
	if a.jwtSecret == nil {
		return Result{}
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(bearer, claims, func(t *jwt.Token) (any, error) {
		return a.jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}), jwt.WithLeeway(leeway))
	if err != nil {
		return Result{}
	}
	return Result{Claims: claims}
}
