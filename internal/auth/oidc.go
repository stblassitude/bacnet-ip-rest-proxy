package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer is one OpenID Connect issuer whose access tokens are accepted.
type Issuer struct {
	// URL is the issuer identifier; tokens' iss claim must equal it, and
	// its signing keys are found via URL + "/.well-known/openid-configuration".
	URL string
	// Audience must be one of the token's aud values.
	Audience string
}

const (
	// keysMaxAge is how long fetched signing keys are used before they're
	// re-fetched on the next token, so keys the issuer has withdrawn stop
	// being accepted.
	keysMaxAge = time.Hour
	// minRefreshInterval rate-limits re-fetching keys on account of a token
	// signed with an unknown key ID (which is how rotation shows up), so
	// tokens with made-up key IDs can't make the proxy hammer the issuer.
	minRefreshInterval = time.Minute
	// fetchTimeout bounds discovery plus JWKS retrieval.
	fetchTimeout = 10 * time.Second
	// maxDocumentSize bounds the discovery document and JWKS we read.
	maxDocumentSize = 1 << 20
	// leeway is the clock skew tolerated for exp, nbf and iat.
	leeway = time.Minute
)

// asymmetricAlgs are the signature algorithms accepted from an issuer.
// HMAC and "none" are excluded: an issuer's keys are public, so accepting
// HS256 "signed" with one would let anyone forge tokens.
var asymmetricAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// oidcVerifier verifies access tokens from one issuer, using the signing
// keys published at the jwks_uri of its OpenID Connect discovery document.
type oidcVerifier struct {
	issuer Issuer
	client *http.Client
	// maxAge and minRefresh default to keysMaxAge and minRefreshInterval.
	maxAge, minRefresh time.Duration

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey // kid -> key; "" for keys without a kid
	fetched     time.Time                   // when keys was last fetched successfully
	lastAttempt time.Time                   // when a fetch was last started
	inflight    chan struct{}               // closed when the running fetch ends
}

func newOIDCVerifier(issuer Issuer, client *http.Client) *oidcVerifier {
	return &oidcVerifier{issuer: issuer, client: client, maxAge: keysMaxAge, minRefresh: minRefreshInterval}
}

// verify validates token's signature and claims, returning its claims.
func (v *oidcVerifier) verify(ctx context.Context, token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(asymmetricAlgs),
		jwt.WithIssuer(v.issuer.URL),
		jwt.WithAudience(v.issuer.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
	)
	_, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.key(ctx, kid)
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// key returns the signing key with ID kid. A known key is returned at once,
// kicking off a background re-fetch if the keys are older than keysMaxAge.
// An unknown kid (which is how key rotation shows up) waits for a fetch,
// rate-limited to one per minRefreshInterval; concurrent callers share it.
func (v *oidcVerifier) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	if k, ok := v.keys[kid]; ok {
		if time.Since(v.fetched) > v.maxAge {
			v.startFetchLocked()
		}
		v.mu.Unlock()
		return k, nil
	}
	done := v.inflight
	if done == nil {
		done = v.startFetchLocked()
	}
	v.mu.Unlock()

	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no signing key with ID %q from issuer %s", kid, v.issuer.URL)
}

// startFetchLocked starts fetching the keys in the background unless one is
// running or the last started less than minRefreshInterval ago. It returns
// a channel closed when the fetch ends, or nil if none was started.
func (v *oidcVerifier) startFetchLocked() chan struct{} {
	if v.inflight != nil || time.Since(v.lastAttempt) < v.minRefresh {
		return v.inflight
	}
	v.lastAttempt = time.Now()
	done := make(chan struct{})
	v.inflight = done
	go func() {
		keys, err := v.fetchKeys(context.Background())
		v.mu.Lock()
		defer v.mu.Unlock()
		if err != nil {
			slog.Warn("fetching OIDC signing keys failed; keeping previous keys", "issuer", v.issuer.URL, "err", err)
		} else {
			if v.keys == nil {
				slog.Info("fetched OIDC signing keys", "issuer", v.issuer.URL, "keys", len(keys))
			}
			v.keys = keys
			v.fetched = time.Now()
		}
		v.inflight = nil
		close(done)
	}()
	return done
}

// prefetch fetches the issuer's keys ahead of the first token, so that
// token isn't delayed and configuration problems are logged at startup.
func (v *oidcVerifier) prefetch() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.startFetchLocked()
}

// fetchKeys runs discovery and fetches the JWKS.
func (v *oidcVerifier) fetchKeys(ctx context.Context) (map[string]crypto.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	discoveryURL := strings.TrimSuffix(v.issuer.URL, "/") + "/.well-known/openid-configuration"
	if err := v.getJSON(ctx, discoveryURL, &discovery); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// OpenID Connect Discovery 1.0 section 4.3: the document must name
	// exactly the issuer it was fetched for.
	if discovery.Issuer != v.issuer.URL {
		return nil, fmt.Errorf("discovery document at %s names issuer %q, not %q", discoveryURL, discovery.Issuer, v.issuer.URL)
	}
	if err := CheckFetchURL(discovery.JWKSURI); err != nil {
		return nil, fmt.Errorf("discovery document's jwks_uri: %w", err)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := v.getJSON(ctx, discovery.JWKSURI, &jwks); err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, raw := range jwks.Keys {
		kid, key, err := parseJWK(raw)
		if err != nil {
			slog.Debug("skipping unusable JWK", "issuer", v.issuer.URL, "kid", kid, "err", err)
			continue
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS at %s has no usable signing keys", discovery.JWKSURI)
	}
	return keys, nil
}

func (v *oidcVerifier) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocumentSize)).Decode(out); err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	return nil
}

// CheckFetchURL reports whether u is acceptable to fetch issuer metadata
// from: an absolute https URL, or http only for a loopback host (for local
// testing).
func CheckFetchURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", u)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		switch parsed.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("%q must use https", u)
	default:
		return fmt.Errorf("%q must use https", u)
	}
}

// parseJWK converts one signature-verification JWK (RFC 7517/7518/8037) to
// a public key, returning its kid.
func parseJWK(raw json.RawMessage) (string, crypto.PublicKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Crv string `json:"crv"`
		N   string `json:"n"`
		E   string `json:"e"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return "", nil, err
	}
	if jwk.Use != "" && jwk.Use != "sig" {
		return jwk.Kid, nil, fmt.Errorf("key use %q is not sig", jwk.Use)
	}
	b64 := base64.RawURLEncoding.DecodeString
	switch jwk.Kty {
	case "RSA":
		n, err1 := b64(jwk.N)
		e, err2 := b64(jwk.E)
		if err := errors.Join(err1, err2); err != nil {
			return jwk.Kid, nil, err
		}
		if len(n)*8 < 2048 {
			return jwk.Kid, nil, fmt.Errorf("RSA key shorter than 2048 bits")
		}
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
			return jwk.Kid, nil, fmt.Errorf("unsupported RSA exponent")
		}
		return jwk.Kid, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return jwk.Kid, nil, fmt.Errorf("unsupported curve %q", jwk.Crv)
		}
		x, err1 := b64(jwk.X)
		y, err2 := b64(jwk.Y)
		if err := errors.Join(err1, err2); err != nil {
			return jwk.Kid, nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) != size || len(y) != size {
			return jwk.Kid, nil, fmt.Errorf("EC coordinates have the wrong length for %s", jwk.Crv)
		}
		// Validates that the point is on the curve.
		key, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return jwk.Kid, nil, err
		}
		return jwk.Kid, key, nil
	case "OKP":
		if jwk.Crv != "Ed25519" {
			return jwk.Kid, nil, fmt.Errorf("unsupported OKP curve %q", jwk.Crv)
		}
		x, err := b64(jwk.X)
		if err != nil {
			return jwk.Kid, nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return jwk.Kid, nil, fmt.Errorf("Ed25519 key has the wrong length")
		}
		return jwk.Kid, ed25519.PublicKey(x), nil
	default:
		return jwk.Kid, nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
	}
}
